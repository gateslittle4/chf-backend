// audit.js -- comparaison "avant / après" des dossiers, fiches et catalogue, pour que le serveur
// note lui-même QUI a créé, modifié ou supprimé quoi, sans dépendre du navigateur. Fonctions pures
// (aucun accès à la base) : server.js les appelle et se charge d'écrire dans audit_log.

// Colonnes qui changent à chaque écriture sans que ce soit une vraie modification du dossier.
const CHAMPS_IGNORES = new Set(['fiches', 'id', 'created_at', 'updated_at', 'timestamp', 'modifie_par', 'modifie_par_uid']);
// Marques posées par le serveur sur chaque fiche -- jamais prises pour une modification de contenu.
const MARQUES_FICHE = ['creePar', 'creeParUid', 'creeLe', 'modifiePar', 'modifieParUid', 'modifieLe'];

function stringifierStable(valeur) {
  if (Array.isArray(valeur)) return '[' + valeur.map(stringifierStable).join(',') + ']';
  if (valeur && typeof valeur === 'object') {
    return '{' + Object.keys(valeur).sort().map(k => JSON.stringify(k) + ':' + stringifierStable(valeur[k])).join(',') + '}';
  }
  return JSON.stringify(valeur === undefined ? null : valeur);
}

const estDate = (v) => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}/.test(v);
const estNumerique = (v) => (typeof v === 'number' && Number.isFinite(v)) || (typeof v === 'string' && v.trim() !== '' && Number.isFinite(Number(v)));

// Deux valeurs sont "égales" même si la base renvoie "82165" pour 82165 ou une date sous un autre
// format -- sinon chaque sauvegarde passerait pour une modification de tous les champs.
function memeValeur(a, b) {
  const vide = (v) => v === null || v === undefined || v === '';
  if (vide(a) && vide(b)) return true;
  if (vide(a) || vide(b)) return false;
  if (estNumerique(a) && estNumerique(b)) return Number(a) === Number(b);
  if (estDate(a) && estDate(b)) return Date.parse(a.replace(' ', 'T')) === Date.parse(b.replace(' ', 'T'));
  return stringifierStable(a) === stringifierStable(b);
}

const court = (v) => {
  if (v === null || v === undefined) return null;
  if (typeof v === 'object') { const s = stringifierStable(v); return s.length > 200 ? s.slice(0, 200) + '…' : s; }
  const s = String(v);
  return s.length > 200 ? s.slice(0, 200) + '…' : v;
};

// Champs du dossier réellement modifiés ({ champ: [avant, après] }). Le corps d'un PUT peut être
// partiel : on ne compare que les champs envoyés.
function diffChamps(avant, corps) {
  const champs = {};
  for (const cle of Object.keys(corps || {})) {
    if (CHAMPS_IGNORES.has(cle)) continue;
    if (!memeValeur(avant ? avant[cle] : undefined, corps[cle])) champs[cle] = [court(avant ? avant[cle] : undefined), court(corps[cle])];
  }
  return champs;
}

const lignesDe = (fiche) => (fiche && fiche.rawState && Array.isArray(fiche.rawState.lignesCalcul)) ? fiche.rawState.lignesCalcul : [];
const texteLigne = (l) => `${l.nom} x${Number(l.qte) || 0} @${Number(l.prix) || 0}`;
const cleLigne = (l) => `${l.type || ''}|${l.itemId != null ? l.itemId : l.nom}`;

// Contenu d'une fiche sans les marques du serveur ni son numéro (renuméroter n'est pas modifier).
function contenuFiche(fiche) {
  const copie = { ...fiche };
  for (const m of MARQUES_FICHE) delete copie[m];
  delete copie.numeroFiche;
  delete copie.creePar;
  return stringifierStable(copie);
}

function resumeFiche(fiche) {
  return {
    numeroFiche: fiche.numeroFiche,
    totalGlobal: Number(fiche.totalGlobal) || 0,
    lignes: lignesDe(fiche).map(texteLigne)
  };
}

function diffLignes(avant, apres) {
  const ancien = new Map(lignesDe(avant).map(l => [cleLigne(l), l]));
  const nouveau = new Map(lignesDe(apres).map(l => [cleLigne(l), l]));
  const ajoutees = [], retirees = [], modifiees = [];
  for (const [cle, l] of nouveau) {
    const o = ancien.get(cle);
    if (!o) ajoutees.push(texteLigne(l));
    else if ((Number(o.qte) || 0) !== (Number(l.qte) || 0) || (Number(o.prix) || 0) !== (Number(l.prix) || 0)) {
      modifiees.push(`${l.nom} : x${Number(o.qte) || 0} @${Number(o.prix) || 0} → x${Number(l.qte) || 0} @${Number(l.prix) || 0}`);
    }
  }
  for (const [cle, o] of ancien) if (!nouveau.has(cle)) retirees.push(texteLigne(o));
  return { ajoutees, retirees, modifiees };
}

function indexerFiches(fiches) {
  const index = new Map();
  (fiches || []).forEach((f, i) => index.set(f && f.id != null ? String(f.id) : `sans-id-${i}`, f));
  return index;
}

// Compare les fiches d'un dossier avant/après : ajoutées, supprimées, modifiées (contenu),
// et nombre de fiches simplement renumérotées.
function comparerFiches(avantFiches, apresFiches) {
  const avant = indexerFiches(avantFiches), apres = indexerFiches(apresFiches);
  const ajoutees = [], supprimees = [], modifiees = [];
  let renumerotees = 0;
  for (const [id, f] of apres) {
    const o = avant.get(id);
    if (!o) { ajoutees.push(f); continue; }
    if (contenuFiche(o) !== contenuFiche(f)) modifiees.push({ avant: o, apres: f });
    else if (o.numeroFiche !== f.numeroFiche) renumerotees++;
  }
  for (const [id, o] of avant) if (!apres.has(id)) supprimees.push(o);
  return { ajoutees, supprimees, modifiees, renumerotees };
}

// Pose les marques "qui" sur les fiches reçues : une nouvelle fiche reçoit creePar/creeLe, une fiche
// modifiée reçoit modifiePar/modifieLe, et les marques déjà posées sont toujours reprises de la base
// (le navigateur envoie creePar:"inconnu" pour tout le monde faute de nom d'affichage).
function tamponnerFiches(avantFiches, apresFiches, acteur, maintenant) {
  if (!Array.isArray(apresFiches)) return apresFiches;
  const avant = indexerFiches(avantFiches);
  return apresFiches.map((f, i) => {
    if (!f || typeof f !== 'object') return f;
    const id = f.id != null ? String(f.id) : `sans-id-${i}`;
    const o = avant.get(id);
    const sortie = { ...f };
    if (!o) {
      sortie.creePar = acteur.nom;
      sortie.creeParUid = acteur.uid;
      sortie.creeLe = maintenant;
      return sortie;
    }
    for (const m of MARQUES_FICHE) { if (o[m] !== undefined) sortie[m] = o[m]; else delete sortie[m]; }
    if (o.creePar === undefined && f.creePar !== undefined) sortie.creePar = f.creePar;
    if (contenuFiche(o) !== contenuFiche(sortie)) {
      sortie.modifiePar = acteur.nom;
      sortie.modifieParUid = acteur.uid;
      sortie.modifieLe = maintenant;
    }
    return sortie;
  });
}

const identiteDossier = (ligne) => ({
  dossierId: ligne && ligne.id,
  nomPatient: ligne && ligne.nom_patient,
  ongPartenaire: ligne && ligne.ong_partenaire,
  numeroLot: ligne && ligne.numero_lot != null ? ligne.numero_lot : null
});

// Lignes d'audit à écrire pour la création d'un dossier.
function auditCreationDossier(ligne) {
  return [{
    action: 'dossier_cree',
    details: { ...identiteDossier(ligne), nombreFiches: (ligne.fiches || []).length, totalGlobal: Number(ligne.total_global) || 0, statut: ligne.status || null }
  }];
}

// Lignes d'audit à écrire pour la modification d'un dossier : une ligne pour les champs du dossier
// (nom, partenaire, lot, statut, verrou...), et une ligne par fiche ajoutée / modifiée / supprimée.
function auditModificationDossier(avant, apres, corps) {
  const lignes = [];
  const id = identiteDossier({ ...avant, ...apres });
  const champs = diffChamps(avant, corps);
  const cmp = Array.isArray(corps && corps.fiches) ? comparerFiches(avant && avant.fiches, apres && apres.fiches ? apres.fiches : corps.fiches) : { ajoutees: [], supprimees: [], modifiees: [], renumerotees: 0 };
  if (Object.keys(champs).length > 0 || cmp.renumerotees > 0) {
    const details = { ...id, champs };
    if (cmp.renumerotees > 0) details.fichesRenumerotees = cmp.renumerotees;
    lignes.push({ action: 'dossier_modifie', details });
  }
  for (const f of cmp.ajoutees) lignes.push({ action: 'fiche_ajoutee', details: { ...id, ...resumeFiche(f) } });
  for (const { avant: o, apres: f } of cmp.modifiees) {
    lignes.push({ action: 'fiche_modifiee', details: { ...id, numeroFiche: f.numeroFiche, totalAvant: Number(o.totalGlobal) || 0, totalApres: Number(f.totalGlobal) || 0, lignes: diffLignes(o, f) } });
  }
  for (const f of cmp.supprimees) lignes.push({ action: 'fiche_supprimee', details: { ...id, ...resumeFiche(f) } });
  return lignes;
}

function auditSuppressionDossier(avant) {
  return [{
    action: 'dossier_supprime',
    details: { ...identiteDossier(avant), nombreFiches: (avant.fiches || []).length, totalGlobal: Number(avant.total_global) || 0, statut: avant.status || null, copieConservee: true }
  }];
}

// Catalogue : ce qui compte pour l'audit est l'ajout / retrait d'un article et ses changements de
// nom, de prix ou de "nouveau prix" -- pas le stock ni le compteur d'utilisations, qui bougent à
// chaque vente.
function diffCatalogue(avantItems, apresItems) {
  const ancien = new Map((avantItems || []).map(i => [String(i.id), i]));
  const nouveau = new Map((apresItems || []).map(i => [String(i.id), i]));
  const ajoutes = [], supprimes = [], modifies = [];
  for (const [id, i] of nouveau) {
    const o = ancien.get(id);
    if (!o) { ajoutes.push(`${i.nom} @${i.prix}`); continue; }
    const changements = [];
    if (o.nom !== i.nom) changements.push(`nom : ${o.nom} → ${i.nom}`);
    for (const champ of ['prix', 'nouveauPrix', 'cout']) {
      if (!memeValeur(o[champ], i[champ])) changements.push(`${champ} : ${o[champ] == null ? '—' : o[champ]} → ${i[champ] == null ? '—' : i[champ]}`);
    }
    if (changements.length) modifies.push(`${i.nom} (${changements.join(', ')})`);
  }
  for (const [id, o] of ancien) if (!nouveau.has(id)) supprimes.push(`${o.nom} @${o.prix}`);
  return { ajoutes, supprimes, modifies };
}

module.exports = {
  memeValeur, diffChamps, comparerFiches, tamponnerFiches, diffLignes, resumeFiche, diffCatalogue,
  auditCreationDossier, auditModificationDossier, auditSuppressionDossier
};
