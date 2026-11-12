require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const admin = require('firebase-admin');
const {
  tamponnerFiches, diffCatalogue, auditCreationDossier, auditModificationDossier, auditSuppressionDossier
} = require('./audit');

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

// `Date` exposé : l'appli s'en sert pour mesurer l'écart entre l'horloge d'un portable et celle du serveur.
app.use(cors({ exposedHeaders: ['Date'] }));
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

// --- Traçabilité : le serveur note lui-même QUI crée, modifie ou supprime un dossier, une fiche, le
// catalogue ou un paiement. L'identité vient toujours du token vérifié (jamais du corps de la
// requête, pour qu'on ne puisse pas l'usurper), et rien ne dépend du navigateur qui "pense" à
// journaliser. Détail des comparaisons avant/après : audit.js.
const acteurDe = (req) => ({ nom: req.user.name || req.user.email || 'inconnu', uid: req.user.uid });

// Écrit des lignes dans audit_log. Ne fait JAMAIS échouer la requête principale : une panne du
// journal ne doit pas empêcher d'enregistrer un patient ou une facture, mais elle est écrite dans
// les journaux du serveur pour qu'on la voie.
async function journaliser(req, lignes) {
  if (!lignes || lignes.length === 0) return;
  try {
    const { nom, uid } = acteurDe(req);
    const { error } = await supabase.from('audit_log').insert(
      lignes.map(l => ({ action: l.action, details: l.details, effectue_par: nom, effectue_par_uid: uid }))
    );
    if (error) console.error('Audit non enregistré :', error.message);
  } catch (e) { console.error('Audit non enregistré :', e.message); }
}

// Lecture de l'état AVANT une écriture (pour comparer). undefined = lecture impossible (on ne
// doit alors ni tamponner les fiches ni comparer, sous peine de les attribuer à tort à la
// personne qui sauvegarde) ; null = dossier introuvable.
async function lireDossier(id) {
  try {
    const { data, error } = await supabase.from('episodes').select('*').eq('id', id).maybeSingle();
    if (error) { console.error('Lecture du dossier avant écriture impossible :', error.message); return undefined; }
    return data || null;
  } catch (e) { console.error('Lecture du dossier avant écriture impossible :', e.message); return undefined; }
}

// Route : version (updated_at) d'un dossier, sans télécharger ses fiches -- l'appli s'en sert pour savoir si un
// dossier a changé depuis qu'une modification hors ligne a été faite, avant de la rejouer.
app.get('/api/episodes/:id/version', async (req, res) => {
  const { data, error } = await supabase.from('episodes').select('id, updated_at, modifie_par').eq('id', req.params.id).maybeSingle();
  if (error) return res.status(500).json({ error: error.message });
  if (!data) return res.status(404).json({ error: 'Dossier introuvable' });
  res.json(data);
});

// Route : création d'un épisode
app.post('/api/episodes', requireRole(...PEUT_GERER_DOSSIERS), async (req, res) => {
  const acteur = acteurDe(req);
  const maintenant = new Date().toISOString();
  const estListe = Array.isArray(req.body);
  const aInserer = (estListe ? req.body : [req.body]).map(l => (
    l && Array.isArray(l.fiches)
      ? { ...l, fiches: tamponnerFiches([], l.fiches, acteur, maintenant), modifie_par: acteur.nom, modifie_par_uid: acteur.uid }
      : l
  ));
  const { data, error } = await supabase
    .from('episodes')
    .insert(estListe ? aInserer : aInserer[0])
    .select();
  if (error) return res.status(500).json({ error: error.message });
  await journaliser(req, data.flatMap(auditCreationDossier));
  res.status(201).json(data[0]);
});

// Route : mise à jour d'un épisode. Trace systématiquement QUI modifie ce dossier (modifie_par) et
// chaque fiche (creePar / modifiePar), et écrit dans audit_log ce qui a changé : champs du dossier,
// fiches ajoutées / modifiées (lignes ajoutées, retirées, prix changés) / supprimées. Couvre TOUTE
// écriture sur un dossier (sauvegarde de fiche, archivage, suspension, report, renommage, lot...).
app.put('/api/episodes/:id', requireRole(...PEUT_GERER_DOSSIERS), async (req, res) => {
  const { id } = req.params;
  const acteur = acteurDe(req);
  // `expected_updated_at` : la version du dossier que le navigateur a ouverte. Si elle est fournie et que
  // le dossier a changé depuis (autre navigateur, autre personne, correction faite côté serveur), la
  // modification est REFUSÉE (409) au lieu d'écraser en silence ce qui a été fait entre-temps. Sans ce champ
  // (ancienne version de l'appli encore ouverte, écritures partielles : lot, archivage...), rien ne change.
  const { expected_updated_at: versionAttendue, ...corps } = req.body || {};
  // Mode strict (variable d'environnement EXIGER_VERSION_DOSSIER=1) : toute écriture de FICHES doit annoncer la
  // version qu'elle modifie. Ça arrête aussi les anciennes versions de l'appli restées ouvertes (portable
  // resté hors ligne, onglet oublié) dont les modifications en attente écraseraient sinon, au retour de la
  // connexion, ce qui a été fait entre-temps : elles sont refusées, et l'appli les garde en quarantaine.
  if (process.env.EXIGER_VERSION_DOSSIER === '1' && Array.isArray(corps.fiches) && !versionAttendue) {
    await journaliser(req, [{ action: 'modification_refusee_sans_version', details: { dossierId: id, nombreFiches: corps.fiches.length } }]);
    return res.status(409).json({ error: "Cette version de l'application est trop ancienne pour enregistrer des fiches en sécurité (elle pourrait écraser le travail fait ailleurs). Tes changements n'ont PAS été enregistrés : recharge la page (Ctrl+Maj+R), rouvre le dossier et refais-les.", conflit: true, versionRequise: true });
  }
  const avant = await lireDossier(id);
  const payload = { ...corps, modifie_par: acteur.nom, modifie_par_uid: acteur.uid };
  if (avant && Array.isArray(payload.fiches)) {
    payload.fiches = tamponnerFiches(avant.fiches, payload.fiches, acteur, new Date().toISOString());
  }
  // Mise à jour conditionnelle ATOMIQUE : "... WHERE id = ? AND updated_at = <version attendue>", donc même
  // deux sauvegardes simultanées ne peuvent pas s'écraser (la seconde ne trouve plus la bonne version).
  let requete = supabase.from('episodes').update(payload).eq('id', id);
  if (versionAttendue) requete = requete.eq('updated_at', versionAttendue);
  const { data, error } = await requete.select();
  if (error) return res.status(500).json({ error: error.message });
  if (versionAttendue && (!data || data.length === 0)) {
    const courant = await lireDossier(id);
    const quand = courant && courant.updated_at ? new Date(courant.updated_at).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', timeZone: 'America/Port-au-Prince' }) : null;
    const message = courant
      ? `Ce dossier a été modifié ailleurs${courant.modifie_par ? ` par ${courant.modifie_par}` : ''}${quand ? ` à ${quand}` : ''} depuis que tu l'as ouvert ici. Tes changements n'ont PAS été enregistrés : recharge la page pour voir la dernière version, puis refais-les.`
      : "Ce dossier n'existe plus (supprimé ailleurs). Tes changements n'ont PAS été enregistrés.";
    await journaliser(req, [{ action: 'modification_refusee_conflit', details: { dossierId: id, nomPatient: courant ? courant.nom_patient : null, versionAttendue, versionActuelle: courant ? courant.updated_at : null, modifieParActuel: courant ? courant.modifie_par : null } }]);
    return res.status(409).json({ error: message, conflit: true, courant: courant ? { updated_at: courant.updated_at, modifie_par: courant.modifie_par } : null });
  }
  const apres = data[0];
  if (avant && apres) await journaliser(req, auditModificationDossier(avant, apres, corps));
  else if (apres) await journaliser(req, [{ action: 'dossier_modifie', details: { dossierId: id, nomPatient: apres.nom_patient, ongPartenaire: apres.ong_partenaire, comparaisonIndisponible: true } }]);
  res.json(apres || {});
});

// Route : suppression d'un épisode. Une copie complète du dossier (toutes ses fiches) est gardée
// dans episodes_supprimes AVANT l'effacement, pour pouvoir dire qui l'a supprimé, quand, et le
// restaurer. Si cette copie échoue, la suppression a quand même lieu (on ne bloque pas le travail)
// mais la copie est alors placée dans le journal d'audit pour ne rien perdre.
app.delete('/api/episodes/:id', requireRole(...PEUT_SUPPRIMER), async (req, res) => {
  const { id } = req.params;
  const acteur = acteurDe(req);
  const avant = await lireDossier(id);
  let copieConservee = false;
  if (avant) {
    const { error: erreurCopie } = await supabase.from('episodes_supprimes').insert({
      episode_id: avant.id, nom_patient: avant.nom_patient, ong_partenaire: avant.ong_partenaire,
      snapshot: avant, supprime_par: acteur.nom, supprime_par_uid: acteur.uid
    });
    if (erreurCopie) console.error('Copie du dossier supprimé non enregistrée :', erreurCopie.message);
    else copieConservee = true;
  }
  const { error } = await supabase.from('episodes').delete().eq('id', id);
  if (error) return res.status(500).json({ error: error.message });
  if (avant) {
    const lignes = auditSuppressionDossier(avant);
    lignes[0].details.copieConservee = copieConservee;
    if (!copieConservee) lignes[0].details.copieDansAudit = avant;
    await journaliser(req, lignes);
  } else {
    await journaliser(req, [{ action: 'dossier_supprime', details: { dossierId: id, dossierIntrouvable: true } }]);
  }
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

// Route : mise à jour du catalogue. Note dans audit_log les articles ajoutés / retirés et les
// changements de nom, de prix ou de "nouveau prix" (pas le stock, qui bouge à chaque vente).
app.put('/api/catalog/:type', requireRole(...PEUT_GERER_CATALOGUE), async (req, res) => {
  const { type } = req.params;
  const { items } = req.body;
  let avantItems;
  try {
    const { data } = await supabase.from('catalog').select('items').eq('type', type).maybeSingle();
    avantItems = data ? data.items : undefined;
  } catch (e) { console.error('Lecture du catalogue avant écriture impossible :', e.message); }
  const { error } = await supabase
    .from('catalog')
    .update({ items, updated_at: new Date().toISOString() })
    .eq('type', type);
  if (error) return res.status(500).json({ error: error.message });
  if (Array.isArray(avantItems) && Array.isArray(items)) {
    const { ajoutes, supprimes, modifies } = diffCatalogue(avantItems, items);
    if (ajoutes.length || supprimes.length || modifies.length) {
      await journaliser(req, [{ action: 'catalogue_modifie', details: {
        catalogue: type,
        ajoutes: ajoutes.slice(0, 50), supprimes: supprimes.slice(0, 50), modifies: modifies.slice(0, 50),
        totalChangements: ajoutes.length + supprimes.length + modifies.length
      } }]);
    }
  }
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
  await journaliser(req, data.map(p => ({ action: 'paiement_enregistre', details: {
    paiementId: p.id, dossierId: p.episode_id, nomPatient: p.patient_nom, montant: Number(p.montant) || 0,
    mode: p.mode, ongPartenaire: p.ong_partenaire
  } })));
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

// Route : changement du mot de passe d'un utilisateur (compte Firebase) -- réservée aux
// administrateurs. Firebase ne permet pas à un navigateur de changer le mot de passe d'un AUTRE
// compte : seul le SDK Admin (ici, côté serveur) le peut. Le mot de passe n'est ni enregistré ni
// écrit dans le journal d'audit, seulement le fait que l'action a eu lieu et sur quel compte.
app.put('/api/users/:uid/password', requireRole('administrateur'), async (req, res) => {
  const { uid } = req.params;
  const { password } = req.body || {};
  if (typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ error: 'Mot de passe : 8 caractères minimum.' });
  }
  try {
    await admin.auth().updateUser(uid, { password });
    // Déconnecte les autres appareils de ce compte : l'ancien mot de passe ne doit plus servir.
    // Pas pour son propre compte, pour ne pas se déconnecter soi-même en plein travail.
    if (uid !== req.user.uid) await admin.auth().revokeRefreshTokens(uid);
  } catch (error) {
    console.error('Erreur changement de mot de passe :', error.code || error.message);
    if (error.code === 'auth/user-not-found') return res.status(404).json({ error: 'Utilisateur introuvable.' });
    if (error.code === 'auth/invalid-password') return res.status(400).json({ error: 'Mot de passe refusé : trop faible ou invalide.' });
    return res.status(500).json({ error: 'Impossible de changer le mot de passe pour le moment.' });
  }
  const { error: erreurAudit } = await supabase.from('audit_log').insert({
    action: 'changement_mot_de_passe',
    details: { utilisateurCible: uid },
    effectue_par: req.user.name || req.user.email || 'inconnu',
    effectue_par_uid: req.user.uid
  });
  if (erreurAudit) console.error('Audit du changement de mot de passe non enregistré :', erreurAudit.message);
  res.json({ success: true });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Backend CHF demarré sur le port ${PORT}`);
});