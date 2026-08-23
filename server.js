require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const admin = require('firebase-admin');

// Initialisation de Firebase Admin pour la vérification des tokens
admin.initializeApp({
  credential: admin.credential.applicationDefault(),
  projectId: 'chf-verification'
});

const app = express();
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

app.use(cors());
app.use(express.json({ limit: '10mb' }));

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
    next();
  } catch (error) {
    console.error('Erreur récupération rôle:', error);
    return res.status(500).json({ error: 'Impossible de vérifier les droits de l\'utilisateur' });
  }
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
const PEUT_GERER_CATALOGUE = ['administrateur', 'direction'];

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

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Backend CHF demarré sur le port ${PORT}`);
});