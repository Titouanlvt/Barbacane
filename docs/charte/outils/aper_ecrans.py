#!/usr/bin/env python3
"""Écrit les maquettes d'écrans (components/Ecran*/ et Serveur*/preview.html), 1280 × 768.

Les maquettes n'utilisent que bundle.css (et sprites.css pour les objets 3D) : ce qui s'y voit
est ce que la borne (iced) et le serveur (HTML + CSS) doivent reproduire.
"""
import pathlib

COMP = pathlib.Path(__file__).resolve().parent.parent / "components"

LOGO = ('<svg viewBox="0 0 64 64" width="34" height="34" aria-hidden="true"><path fill="currentColor" fill-rule="evenodd" '
        'd="M6 58V12h4v4h4v-4h4v4h4v42ZM12.5 26v10h3V26ZM42 58V16h4v-4h4v4h4v-4h4v46ZM48.5 26v10h3V26ZM22 58V24h20v34ZM27 58V43a5 5 0 0 1 10 0v15Z"/>'
        '<rect x="27" y="46" width="10" height="2" fill="var(--laiton-clair)"/><rect x="27" y="51" width="10" height="2" fill="var(--laiton-clair)"/></svg>')
IC = {
    "shield": '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/>',
    "octo": '<path d="m15 9-6 6"/><path d="M2.586 16.726A2 2 0 0 1 2 15.312V8.688a2 2 0 0 1 .586-1.414l4.688-4.688A2 2 0 0 1 8.688 2h6.624a2 2 0 0 1 1.414.586l4.688 4.688A2 2 0 0 1 22 8.688v6.624a2 2 0 0 1-.586 1.414l-4.688 4.688a2 2 0 0 1-1.414.586H8.688a2 2 0 0 1-1.414-.586z"/><path d="m9 9 6 6"/>',
    "usb": '<circle cx="10" cy="7" r="1"/><circle cx="4" cy="20" r="1"/><path d="M4.7 19.3 19 5"/><path d="m21 3-3 1 2 2Z"/><path d="M9.26 7.68 5 12l2 5"/><path d="m10 14 5 2 3.5-3.5"/><path d="m18 12 1-1 1 1-1 1Z"/>',
    "disc": '<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="2"/>',
    "server": '<rect width="20" height="8" x="2" y="2" rx="2"/><rect width="20" height="8" x="2" y="14" rx="2"/><path d="M6 6h.01M6 18h.01"/>',
    "grid": '<rect width="7" height="7" x="3" y="3" rx="1"/><rect width="7" height="7" x="14" y="3" rx="1"/><rect width="7" height="7" x="14" y="14" rx="1"/><rect width="7" height="7" x="3" y="14" rx="1"/>',
    "users": '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/>',
    "file": '<path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"/><path d="M14 2v4a2 2 0 0 0 2 2h4"/>',
    "up": '<path d="M12 3v12"/><path d="m17 8-5-5-5 5"/><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>',
    "list": '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
    "shield2": '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>',
}


def ic(k, cls=""):
    return f'<svg viewBox="0 0 24 24" class="{cls}" aria-hidden="true" style="width:1em;height:1em;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round">{IC[k]}</svg>'


def bandeau(droite='B-A-01 · Site A'):
    return (f'<header class="b-bandeau">{LOGO}<span class="b-bandeau__nom">Barbacane</span>'
            f'<span class="b-bandeau__plus"><span class="b-mono" style="opacity:.8">{droite}</span></span></header>')


def pied(etat='<span class="b-etat b-etat--sain" style="--c:var(--sain)">Serveur connecté</span>'):
    return (f'<footer style="display:flex;justify-content:space-between;align-items:center;padding:0 24px;height:44px;font-size:15px;color:var(--encre-douce)">'
            f'<span>Barbacane 2.0 · station blanche</span><span style="display:flex;gap:24px;align-items:center">{etat}'
            f'<button class="b-btn b-btn--discret" style="min-height:44px;font-size:15px;padding:0 8px">Administration</button></span></footer>')


def etapes(cours):
    noms = ["Clé insérée", "Analyse", "Résultat", "Sortie", "Copie"]
    li = []
    for i, n in enumerate(noms):
        c = "fait" if i < cours else ("cours" if i == cours else "")
        li.append(f'<li class="{c}"{" aria-current=step" if i == cours else ""}>{n}</li>')
    return f'<ol class="b-etapes" style="margin:16px 64px 0">{"".join(li)}</ol>'


def ecran(corps, sous="", haut=None, bas=None):
    return f"""<!-- @dsCard group="Maquettes · borne" height=780 width=1280 page subtitle="{sous}" -->
<link rel="stylesheet" href="../demo.css?v=2">
<link rel="stylesheet" href="../sprites.css?v=2">
<div class="cadre-ecran b-ecran">
{haut if haut is not None else bandeau()}
{corps}
{bas if bas is not None else pied()}
</div>
"""


M = {}

M["EcranAccueil"] = ecran(f"""
<main style="flex:1;display:grid;place-items:center;align-content:center;gap:8px;text-align:center">
  <div class="b-sprite s-embleme-pivot" style="--cote:300px;--d:3200ms;--iter:infinite;--dir:alternate"></div>
  <h1 style="margin:0;font:600 48px/52px var(--font-display)">Insérez la clé ou le disque à analyser.</h1>
  <p style="margin:0;font-size:22px;color:var(--encre-douce)">Les fichiers sont analysés ici, avant d'aller plus loin.</p>
  <div style="display:flex;gap:32px;margin-top:20px;font-size:20px;color:var(--encre-douce)"><span style="display:flex;gap:8px;align-items:center;font-size:20px">{ic("usb")} Port USB, à droite</span><span style="display:flex;gap:8px;align-items:center">{ic("disc")} Lecteur de disque, en façade</span></div>
</main>""", "Accueil, emblème en veille")

M["EcranAnalyse"] = ecran(f"""
{etapes(1)}
<main style="flex:1;display:grid;grid-template-columns:300px 1fr;gap:40px;align-items:center;padding:0 64px">
  <div style="position:relative;height:300px">
    <div class="b-sprite s-cle" style="--cote:300px;position:absolute;inset:0;animation:none;background-position:calc(300px * -15) 0"></div>
  </div>
  <div style="display:grid;gap:20px">
    <h1 style="margin:0;font:600 48px/52px var(--font-display)">Analyse en cours</h1>
    <p style="margin:0;font-size:22px">SanDisk Ultra · 16 Go · 1 038 fichiers</p>
    <div><div class="b-barre" style="height:28px"><div class="b-barre__rempli" style="--p:38"></div></div>
    <div class="b-barre-legende" style="font-size:18px;line-height:26px"><span>Photos/chantier-04.jpg</span><span>412 / 1 038 · 2 min 14 s · reste ≈ 3 min</span></div></div>
    <div class="b-carte" style="display:flex;gap:32px;padding:16px 24px">
      <span class="b-etat b-etat--sain">409 sains</span><span class="b-etat b-etat--bloque">1 bloqué</span><span class="b-etat b-etat--alerte">2 écartés</span>
    </div>
  </div>
</main>
<div style="display:flex;justify-content:flex-start;padding:0 64px 16px"><button class="b-btn">Annuler l'analyse</button></div>""", "Analyse : clé, barre, compteurs en direct")

CHOIX = """<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:24px">
    <button class="b-choix" style="min-height:132px"><span class="b-choix__titre">{u} Copier vers une clé</span><span class="b-choix__texte">Sur une clé de sortie enrôlée, effacée puis formatée.</span></button>
    <button class="b-choix" style="min-height:132px"><span class="b-choix__titre">{d} Graver un disque</span><span class="b-choix__texte">Sur un CD ou un DVD vierge.</span></button>
    <button class="b-choix b-choix--danger" style="min-height:132px"><span class="b-choix__titre">Blanchir cette clé</span><span class="b-choix__texte">Effacée entièrement, puis seuls les fichiers sains y sont réécrits.</span></button>
  </div>
  <div style="display:flex;justify-content:flex-start"><button class="b-btn">Arrêter ici</button></div>""".format(u=ic("usb"), d=ic("disc"))

M["EcranSain"] = ecran(f"""
{etapes(2)}
<main style="flex:1;display:grid;gap:22px;align-content:center;padding:0 64px">
  <div class="b-verdict b-verdict--sain" style="padding:16px 24px">
    <div class="b-sprite s-bouclier b-sprite--fin" style="--cote:110px;margin:-16px 0"></div>
    <div><p class="b-verdict__titre" style="font-size:56px;line-height:58px">Clé saine</p><p class="b-verdict__texte">Aucune menace. Les 1 038 fichiers peuvent être copiés.</p></div>
  </div>
  <p style="margin:0;font-size:30px;line-height:38px">Que faire des fichiers ?</p>
  {CHOIX}
</main>""", "Verdict sain et choix de la suite")

M["EcranBloque"] = ecran(f"""
{etapes(2)}
<main style="flex:1;display:grid;grid-template-columns:1fr 1fr;gap:28px;align-content:center;padding:0 64px">
  <div style="display:grid;gap:18px;align-content:start">
    <div class="b-verdict b-verdict--bloque" style="padding:16px 22px">
      <span class="b-pastille" style="width:64px;height:64px"><svg viewBox="0 0 24 24">{IC["octo"]}</svg></span>
      <div><p class="b-verdict__titre">2 fichiers bloqués</p><p class="b-verdict__texte">Menace détectée. Ils ne seront pas copiés.</p></div>
    </div>
    <ul class="b-liste">
      <li><div><div class="b-liste__nom">Factures/relance_mars.docm</div><div class="b-liste__detail">ClamAV : Win.Trojan.Agent-1043</div></div><span class="b-etat b-etat--bloque">Bloqué</span></li>
      <li><div><div class="b-liste__nom">mixte.zip/e2</div><div class="b-liste__detail">YARA : Eicar_Test_Signature</div></div><span class="b-etat b-etat--bloque">Bloqué</span></li>
      <li><div><div class="b-liste__nom">Archives/compta-2025.zip</div><div class="b-liste__detail">Archive chiffrée · 12,4 Mo</div></div><span class="b-etat b-etat--alerte">Écarté</span></li>
    </ul>
  </div>
  <div style="display:grid;gap:18px;align-content:start;justify-items:stretch">
    <div class="b-sprite s-embleme-herse b-sprite--fin" style="--cote:230px;justify-self:center;margin:-10px 0 -20px"></div>
    <p style="margin:0;font-size:24px;line-height:32px;text-align:center"><b>1 035 fichiers sains</b> peuvent quand même être copiés.</p>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
      <button class="b-btn">Arrêter ici</button>
      <button class="b-btn b-btn--principal">Choisir la sortie</button>
    </div>
  </div>
</main>""", "Verdict bloqué : panneau, liste, herse fermée")

PAVE = "".join(f'<button class="b-touche" style="width:88px;height:64px">{c}</button>' for c in "123456789")
M["EcranIdentification"] = ecran(f"""
<main style="flex:1;display:grid;grid-template-columns:1fr 1fr;gap:56px;align-items:center;padding:0 96px">
  <div style="display:grid;gap:20px">
    <h1 style="margin:0;font:600 48px/52px var(--font-display)">Identifiez-vous</h1>
    <p style="margin:0;font-size:22px;color:var(--encre-douce)">Cette borne enregistre qui analyse quoi.</p>
    <div class="b-champ"><label for="e-id">Identifiant</label><input id="e-id" class="b-saisie" value="t.lelievre"></div>
    <div class="b-champ"><label for="e-pin">Code PIN Barbacane</label><input id="e-pin" class="b-saisie" type="password" value="1234"><span class="b-aide" style="font-size:18px">4 à 8 chiffres. Ce n'est pas votre mot de passe de session.</span></div>
  </div>
  <div class="b-clavier" style="grid-template-columns:repeat(3,88px);justify-content:center;padding:20px">
    {PAVE}
    <button class="b-touche" style="width:88px;height:64px;font-size:18px">⌫</button><button class="b-touche" style="width:88px;height:64px">0</button><button class="b-touche b-touche--action" style="width:88px;height:64px;font-size:18px">Valider</button>
  </div>
</main>""", "v2 en ligne : identifiant et PIN au pavé tactile")

M["EcranHorsService"] = ecran("""
<main style="flex:1;display:grid;place-items:center;align-content:center;gap:12px;text-align:center;padding:0 120px">
  <div class="b-sprite s-embleme-herse b-sprite--fin" style="--cote:260px"></div>
  <div class="b-verdict" style="--c:var(--hors-service);--f:var(--surface-haute);--fonce:var(--trait-fort);text-align:left;padding:18px 26px">
    <span class="b-pastille" style="--c:var(--hors-service);--fonce:var(--trait-fort)"><svg viewBox="0 0 24 24"><rect width="20" height="8" x="2" y="2" rx="2"/><rect width="20" height="8" x="2" y="14" rx="2"/><path d="M6 6h.01M6 18h.01"/></svg></span>
    <div><p class="b-verdict__titre" style="color:var(--encre)">Borne hors service</p><p class="b-verdict__texte">Le serveur de gestion est injoignable depuis 5 min. Aucune clé ne peut être analysée.</p></div>
  </div>
  <p style="margin:6px 0 0;font-size:20px;color:var(--encre-douce)">Prévenez l'administrateur. La borne reprendra seule dès le retour du serveur.</p>
</main>""", "v2 en ligne : serveur injoignable après le délai de grâce",
    bas=pied('<span class="b-etat b-etat--hors">Serveur injoignable · dernier contact 10:42</span>'))


def serveur(corps, sous, actif):
    liens = [("grid", "Supervision"), ("server", "Bornes"), ("users", "Utilisateurs"), ("usb", "Clés enrôlées"),
             ("file", "Rapports"), ("up", "Mises à jour"), ("shield2", "Politique"), ("list", "Audit")]
    nav = "".join(f'<a href="#"{" aria-current=page" if n == actif else ""}>{ic(k)} {n}</a>' for k, n in liens)
    return f"""<!-- @dsCard group="Maquettes · serveur" height=820 width=1280 page subtitle="{sous}" -->
<link rel="stylesheet" href="../demo.css?v=2">
<div class="b-page" style="width:1280px;min-height:800px">
<div class="b-coque" style="min-height:800px">
  <nav class="b-nav" aria-label="Navigation"><div class="b-nav__marque">{LOGO} Barbacane</div>{nav}
    <div style="margin-top:auto;padding:24px;font-size:13px;opacity:.75">admin.site-a<br>Clé FIDO2 · rôle Administrateur</div></nav>
  <main class="b-contenu">
{corps}
  </main>
</div></div>
"""


M["ServeurSupervision"] = serveur("""
    <div class="b-entete"><div><div class="b-fil">Supervision</div><h1>Bornes · tous les sites</h1></div>
      <div style="display:flex;gap:12px"><button class="b-btn">Exporter</button><button class="b-btn b-btn--principal">Enrôler une borne</button></div></div>
    <div class="b-tuiles">
      <div class="b-tuile"><div class="b-tuile__chiffre">12</div><div class="b-tuile__nom">Bornes enrôlées</div></div>
      <div class="b-tuile" style="--c:var(--sain)"><div class="b-tuile__chiffre">10</div><div class="b-tuile__nom"><span class="b-etat b-etat--sain">En service</span></div></div>
      <div class="b-tuile" style="--c:var(--hors-service)"><div class="b-tuile__chiffre">1</div><div class="b-tuile__nom"><span class="b-etat b-etat--hors">Injoignable</span></div></div>
      <div class="b-tuile" style="--c:var(--menace)"><div class="b-tuile__chiffre">3</div><div class="b-tuile__nom"><span class="b-etat b-etat--bloque">Menaces (24 h)</span></div></div>
      <div class="b-tuile" style="--c:var(--alerte)"><div class="b-tuile__chiffre">1</div><div class="b-tuile__nom"><span class="b-etat b-etat--alerte">Signatures &gt; 7 j</span></div></div>
    </div>
    <div class="b-avis b-avis--alerte"><span><b>À traiter :</b> B-B-01 injoignable depuis 9 min · B-B-02 signatures de 8 jours · 1 enrôlement attend une seconde validation.</span></div>
    <div class="b-tableau-cadre"><table class="b-tableau">
      <thead><tr><th>Borne</th><th>Site</th><th>État</th><th>Mode</th><th>Signatures</th><th class="num">Analyses 24 h</th><th class="num">Bloqués</th><th>Certificat</th><th>Dernier contact</th></tr></thead>
      <tbody>
        <tr><td class="b-mono">B-A-01</td><td>Site A</td><td><span class="b-etat b-etat--sain">En service</span></td><td>Authentification</td><td>il y a 2 h</td><td class="num">142</td><td class="num">0</td><td>71 j</td><td>il y a 30 s</td></tr>
        <tr aria-selected="true"><td class="b-mono">B-A-02</td><td>Site A</td><td><span class="b-etat b-etat--bloque">Menace</span></td><td>Authentification</td><td>il y a 2 h</td><td class="num">87</td><td class="num">2</td><td>71 j</td><td>il y a 12 s</td></tr>
        <tr><td class="b-mono">B-A-03</td><td>Site A</td><td><span class="b-etat b-etat--cours">Mise à jour</span></td><td>Identification</td><td>il y a 2 h</td><td class="num">54</td><td class="num">1</td><td>88 j</td><td>il y a 4 s</td></tr>
        <tr><td class="b-mono">B-B-01</td><td>Site B</td><td><span class="b-etat b-etat--hors">Injoignable</span></td><td>Aucun</td><td>il y a 1 j</td><td class="num">0</td><td class="num">0</td><td>12 j</td><td>il y a 9 min</td></tr>
        <tr><td class="b-mono">B-B-02</td><td>Site B</td><td><span class="b-etat b-etat--alerte">Signatures &gt; 7 j</span></td><td>Identification</td><td>il y a 8 j</td><td class="num">23</td><td class="num">0</td><td>45 j</td><td>il y a 41 s</td></tr>
        <tr><td class="b-mono">B-C-01</td><td>Site C</td><td><span class="b-etat b-etat--sain">En service</span></td><td>Authentification</td><td>il y a 2 h</td><td class="num">96</td><td class="num">0</td><td>63 j</td><td>il y a 18 s</td></tr>
      </tbody></table></div>""", "Supervision : tuiles, à traiter, tableau", "Supervision")

M["ServeurEnrolement"] = serveur("""
    <div class="b-entete"><div><div class="b-fil">Bornes › Enrôler</div><h1>Enrôler une borne</h1></div></div>
    <div style="display:grid;grid-template-columns:560px 1fr;gap:32px;align-items:start">
      <form class="b-carte b-formulaire" onsubmit="return false">
        <div class="b-champ"><label for="s-nom">Nom de la borne</label><input id="s-nom" class="b-saisie" value="B-A-04"><span class="b-aide">Visible dans les rapports et le journal d'audit.</span></div>
        <div class="b-champ"><label for="s-site">Site</label><select id="s-site" class="b-saisie"><option>Site A — Rennes</option></select></div>
        <div class="b-champ"><label for="s-mode">Mode utilisateurs</label><select id="s-mode" class="b-saisie"><option>Authentification (identifiant + PIN)</option></select></div>
        <div class="b-champ b-champ--erreur"><label for="s-duree">Validité du jeton</label><input id="s-duree" class="b-saisie" value="72 h"><span class="b-aide">24 h au plus : le jeton est un secret à usage unique.</span></div>
        <label class="b-case"><input type="checkbox" checked> Inclure le jeton dans une ISO personnalisée</label>
        <div class="b-avis b-avis--alerte"><span>L'enrôlement devra être validé par un second administrateur.</span></div>
        <div class="b-formulaire__actions"><button class="b-btn b-btn--discret" type="button">Annuler</button><button class="b-btn b-btn--principal">Créer le jeton</button></div>
      </form>
      <div class="b-carte" style="display:grid;gap:12px">
        <h2 class="b-carte__titre">Étapes</h2>
        <ol class="b-etapes" style="flex-direction:column;font-size:15px"><li class="fait">Jeton créé</li><li class="cours">Seconde validation</li><li>Borne installée et connectée</li><li>Certificat délivré (90 j)</li></ol>
        <p class="b-douce" style="margin:0">La borne appelle le serveur ; elle n'écoute aucun port. Empreinte du certificat serveur à vérifier à l'installation :</p>
        <p class="b-mono" style="margin:0;font-size:13px;overflow-wrap:anywhere">SHA256 4F:9A:21:C0:7E:55:B3:1D:90:AA:6C:02:E8:17:4B:D9</p>
      </div>
    </div>""", "Formulaire d'enrôlement (double validation)", "Bornes")

for nom, html in M.items():
    (COMP / nom).mkdir(exist_ok=True)
    (COMP / nom / "preview.html").write_text(html, encoding="utf-8")
    print(nom)
