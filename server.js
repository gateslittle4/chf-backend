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

// Application du middleware sur toutes les routes API
app.use('/api', verifyToken);

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
app.post('/api/episodes', async (req, res) => {
  const { data, error } = await supabase
    .from('episodes')
    .insert(req.body)
    .select();
  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json(data[0]);
});

// Route : mise à jour d'un épisode
app.put('/api/episodes/:id', async (req, res) => {
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
app.delete('/api/episodes/:id', async (req, res) => {
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
app.put('/api/catalog/:type', async (req, res) => {
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
app.post('/api/paiements', async (req, res) => {
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