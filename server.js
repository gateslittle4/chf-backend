require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const admin = require('firebase-admin');

// Initialisation de Firebase Admin pour la vérification des tokens. applicationDefault() ne
// fonctionne que sur l'infrastructure Google -- sur Render, il faut fournir explicitement les
// identifiants du compte de service (téléchargés depuis Firebase Console, stockés uniquement en
// variable d'environnement, jamais committés).
admin.initializeApp({
  credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON)),
  projectId: 'chf-verification'
});

const app = express();
// service_role (pas anon) : le backend a besoin d'un accès complet à la base, et c'est LUI qui
// vérifie les droits (voir verifyToken/requireRole ci-dessous) -- Supabase RLS est activé sans
// policy pour anon/authenticated, donc la clé anon (potentiellement exposée un jour) ne pourrait
// plus rien lire ni modifier directement, en contournant cette vérification.
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Route de vérification publique (sans authentification) : répond juste que le processus tourne,
// sans solliciter Firebase ni Supabase. Volontairement en dehors de /api, utile pour un contrôle
// manuel ou par un outil de supervision -- ne PAS y brancher de ping automatique fréquent : les
// heures d'exécution du plan gratuit Render sont limitées par mois pour tout le compte, et
// empêcher la mise en veille consommerait ce quota bien plus vite qu'une utilisation normale.
app.get('/health', (req, res) => res.status(200).json({ status: 'ok' }));

// Middleware de vérification du token JWT Firebase
async function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token manquant ou invalide' });
  }
  const idToken = authHeader.split('Bearer ')[1];
  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    req.user = decodedToken;
    next();
  } catch (error) {
    console.error('Erreur vérification token:', error);
    return res.status(401).json({ error: 'Token invalide ou expiré' });
  }
}

// Le rôle (comptable/direction/administrateur/auditeur) n'existe que dans Firestore, pas dans le
// token Firebase — on va le chercher pour pouvoir restreindre les routes sensibles ci-dessous.
// Sans ça, n'importe quel utilisateur authentifié pouvait appeler directement l'API (suppression de
// dossiers, modification des tarifs...) même si l'interface lui masque ces boutons.
async function chargerRole(req, res, next) {
  try {
    const doc = await admin.firestore().collection('users').doc(req.user.uid).get();
    req.user.role = doc.exists ? (doc.data().role || 'auditeur') : 'auditeur';
  } catch (error) {
    // Panne Firestore (ex: identifiants Google absents sur cet hébergeur) -- ne bloque plus TOUTE
    // l'API : on retombe sur le rôle le moins privilégié (lecture seule) plutôt qu'un 500 général,
    // le temps de configurer les identifiants Firebase Admin correctement sur Render.
    console.error('Erreur récupération rôle (accès en lecture seule appliqué) :', error.message);
    req.user.role = 'auditeur';
  }
  // Esdras (propriétaire du compte) : toujours administrateur, même si Firestore est injoignable
  // ou que son rôle n'y est pas encore configuré -- évite qu'une panne Firestore ou un oubli de
  // configuration ne le fasse tomber en lecture seule (auditeur) sur sa propre application.
  if (req.user.email === 'gateslittle4@gmail.com') req.user.role = 'administrateur';
  next();
}

function requireRole(...rolesAutorises) {
  return (req, res, next) => {
    if (!rolesAutorises.includes(req.user.role)) {
      return res.status(403).json({ error: 'Action non autorisée pour votre rôle' });
    }
    next();
  };
}

const PEUT_GERER_DOSSIERS = ['comptable', 'direction', 'administrateur'];
const PEUT_SUPPRIMER = ['direction', 'administrateur'];
const PEUT_GERER_CATALOGUE = ['administrateur', 'direction', 'comptable'];

// Application du middleware sur toutes les routes API
app.use('/api', verifyToken, chargerRole);

// Route : récupération de tous les épisodes
app.get('/api/episodes', async (req, res) => {
  const { data, error } = await supabase
    .from('episodes')
    .select('*')
    .order('timestamp', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// Route : création d'un épisode
app.post('/api/episodes', requireRole(...PEUT_GERER_DOSSIERS), async (req, res) => {
  const { data, error } = await supabase
    .from('episodes')
    .insert(req.body)
    .select();
  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json(data[0]);
});

// Route : mise à jour d'un épisode
app.put('/api/episodes/:id', requireRole(...PEUT_GERER_DOSSIERS), async (req, res) => {
  const { id } = req.params;
  const { data, error } = await supabase
    .from('episodes')
    .update(req.body)
    .eq('id', id)
    .select();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data[0] || {});
});

// Route : suppression d'un épisode
app.delete('/api/episodes/:id', requireRole(...PEUT_SUPPRIMER), async (req, res) => {
  const { id } = req.params;
  const { error } = await supabase.from('episodes').delete().eq('id', id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// Route : récupération du catalogue (médicaments ou actes)
app.get('/api/catalog/:type', async (req, res) => {
  const { type } = req.params;
  const { data, error } = await supabase
    .from('catalog')
    .select('items')
    .eq('type', type)
    .single();
  if (error && error.code !== 'PGRST116') return res.status(500).json({ error: error.message });
  res.json(data?.items || []);
});

// Route : mise à jour du catalogue
app.put('/api/catalog/:type', requireRole(...PEUT_GERER_CATALOGUE), async (req, res) => {
  const { type } = req.params;
  const { items } = req.body;
  const { error } = await supabase
    .from('catalog')
    .update({ items, updated_at: new Date().toISOString() })
    .eq('type', type);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// Route : récupération des paiements
app.get('/api/paiements', async (req, res) => {
  const { data, error } = await supabase
    .from('paiements')
    .select('*')
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// Route : création d'un paiement
app.post('/api/paiements', requireRole(...PEUT_GERER_DOSSIERS), async (req, res) => {
  const { data, error } = await supabase
    .from('paiements')
    .insert(req.body)
    .select();
  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json(data[0]);
});

// Journal d'audit — miroir Postgres du journal Firestore (voir enregistrerAudit dans
// chf-demo2/api/firebase.js) : double écriture, rien n'est retiré de Firestore. Permet de
// consulter les événements (ajout à un lot, génération de lot, suppression...) directement
// depuis cette base, sans dépendre d'un accès Firestore séparé.
const PEUT_LIRE_AUDIT = ['administrateur', 'direction', 'auditeur'];

// Route : ajout d'un événement au journal d'audit. Tout utilisateur authentifié peut écrire
// (c'est le journal de SES propres actions) -- l'identité vient du token vérifié, jamais du
// corps de la requête, pour qu'on ne puisse pas usurper "effectué par" un autre compte.
app.post('/api/audit', async (req, res) => {
  const { action, details } = req.body;
  if (!action) return res.status(400).json({ error: 'action manquante' });
  const { data, error } = await supabase
    .from('audit_log')
    .insert({
      action,
      details: details || {},
      effectue_par: req.user.name || req.user.email || 'inconnu',
      effectue_par_uid: req.user.uid
    })
    .select();
  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json(data[0]);
});

// Route : lecture du journal d'audit -- réservée aux rôles qui doivent pouvoir le consulter.
app.get('/api/audit', requireRole(...PEUT_LIRE_AUDIT), async (req, res) => {
  const { data, error } = await supabase
    .from('audit_log')
    .select('*')
    .order('date', { ascending: false })
    .limit(500);
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Backend CHF demarré sur le port ${PORT}`);
});