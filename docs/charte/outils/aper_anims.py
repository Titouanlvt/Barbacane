#!/usr/bin/env python3
"""Écrit les aperçus des huit animations clés (components/Anim*/preview.html).

Chaque aperçu : la scène qui boucle, une case « Version réduite » (CSS seul, :has), le
storyboard minuté. Les durées viennent des jetons (duree-*, courbe-*). Aucun JavaScript.
"""
import pathlib

COMP = pathlib.Path(__file__).resolve().parent.parent / "components"

TETE = """<!-- @dsCard group="Animations" height={h} subtitle="{sous}" -->
<link rel="stylesheet" href="../demo.css?v=2">
<link rel="stylesheet" href="../sprites.css?v=2">
<style>
.scene {{ --cyc: {cyc}; }}
.scene .b-sprite {{ position: absolute; }}
.fixe {{ animation: none !important; }}
{css}
/* version réduite : état final, sans mouvement */
.anim:has(.reduire:checked) .scene *, .anim:has(.reduire:checked) .scene *::after {{ animation: none !important; transition: none !important; }}
{reduit}
</style>
<div class="demo anim">
  <label class="opt"><input type="checkbox" class="reduire" id="reduire"> Version réduite (option « Animations réduites » : état final, aucun mouvement)</label>
  <div class="scene" aria-hidden="true">
{scene}
  </div>
  <ol class="story">
{story}
  </ol>
</div>
"""


def story(etapes):
    return "\n".join(f"    <li><b>{t}</b>{d}</li>" for t, d in etapes)


def fin(sel, n):
    """Règle « dernière image » d'une bande."""
    return f"{sel} {{ background-position: calc(var(--cote) * (1 - var(--n))) 0 !important; }}"


A = {}

# 1. Insertion d'une clé ----------------------------------------------------------------
A["AnimInsertion"] = dict(h=600, sous="La clé pivote, glisse et s'enfonce dans la porte", cyc="3200ms", css="""
.cle { --cote: 170px; left: 150px; top: 40px; animation: cle-va var(--cyc) var(--courbe-arrivee) infinite, cle-tourne var(--cyc) steps(16, jump-none) infinite; }
@keyframes cle-va { 0% { transform: translateX(-330px); } 18.75% { transform: translateX(0); } 23.4% { transform: translateX(16px); } 100% { transform: translateX(16px); } }
@keyframes cle-tourne { 0% { background-position: 0 0; } 18.75%, 100% { background-position: calc(var(--cote) * (1 - var(--n))) 0; } }
.porte { --cote: 210px; left: 300px; top: 4px; }
.voyant { position: absolute; left: 389px; top: 200px; width: 30px; height: 8px; border-radius: 4px; background: var(--trait-fort); animation: voyant var(--cyc) steps(1, jump-end) infinite; }
@keyframes voyant { 0%, 23.4% { background: var(--trait-fort); box-shadow: none; } 23.5%, 100% { background: var(--laiton-clair); box-shadow: 0 0 0 3px var(--laiton-pale); } }
.msg { animation: arrive var(--cyc) var(--courbe-arrivee) infinite; }
@keyframes arrive { 0%, 23.4% { transform: translateX(24px); color: transparent; } 32.8%, 100% { transform: none; color: var(--encre); } }
""", reduit=fin(".anim:has(.reduire:checked) .cle", "") + """
.anim:has(.reduire:checked) .cle { transform: translateX(16px); }
.anim:has(.reduire:checked) .voyant { background: var(--laiton-clair); box-shadow: 0 0 0 3px var(--laiton-pale); }
""", scene="""    <div class="b-sprite s-embleme-herse porte fixe"></div>
    <div class="b-sprite s-cle cle"></div>
    <div class="voyant"></div>
    <div class="msg">Clé détectée</div>""", story=story([
    ("0 – 600 ms", "La clé arrive de la gauche (courbe d'arrivée) et pivote de 62° vers la porte : bande <code>cle</code>, 16 images."),
    ("600 – 750 ms", "Elle s'enfonce de 16 px : elle est « entrée »."),
    ("750 ms", "Le voyant de la porte passe au laiton : la borne a reconnu la clé."),
    ("750 – 1 050 ms", "« Clé détectée » arrive de 24 px à droite."),
    ("Réduite", "Clé en place, voyant allumé, texte affiché. Rien ne bouge."),
    ("Logiciel", "1 image de la bande + 1 translation par trame ; zone redessinée ≈ 520 × 200 px."),
]))

# 2. Analyse en cours ----------------------------------------------------------------------
A["AnimAnalyse"] = dict(h=600, sous="Faisceau, parallaxe des fichiers, barre vivante", cyc="1600ms", css="""
.pile { position: absolute; left: 50%; top: 26px; width: 300px; height: 190px; margin-left: -150px; border-radius: 12px; overflow: hidden; }
.lignes { position: absolute; inset: 0 0 -190px 0; padding: 14px 18px; display: grid; gap: 12px; align-content: start; animation: defile 6s linear infinite; }
.lignes i { display: block; height: 10px; border-radius: 5px; background: var(--trait); }
.lignes i:nth-child(3n) { width: 70%; } .lignes i:nth-child(3n+1) { width: 88%; } .lignes i:nth-child(3n+2) { width: 54%; }
@keyframes defile { to { transform: translateY(-190px); } }
.faisceau { position: absolute; left: -8px; right: -8px; top: 0; height: 6px; border-radius: 3px; background: linear-gradient(180deg, color-mix(in srgb, var(--analyse) 60%, #fff), var(--analyse)); box-shadow: 0 0 0 3px var(--analyse-fond); animation: balaie var(--cyc) var(--courbe-arrivee) infinite alternate; }
@keyframes balaie { to { transform: translateY(184px); } }
.cle { --cote: 120px; left: 34px; top: 70px; }
.barre { position: absolute; left: 60px; right: 60px; bottom: 54px; }
.msg { bottom: 4px; font-size: 26px; }
""", reduit="""
.anim:has(.reduire:checked) .faisceau { display: none; }
.anim:has(.reduire:checked) .cle { background-position: calc(var(--cote) * (1 - var(--n))) 0; }
""", scene="""    <div class="b-sprite s-cle cle fixe" style="background-position: calc(120px * -15) 0"></div>
    <div class="pile b-dalle"><div class="lignes"><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i></div><div class="faisceau"></div></div>
    <div class="barre"><div class="b-barre"><div class="b-barre__rempli" style="--p:38"></div></div></div>
    <div class="msg">Analyse en cours · 412 / 1 038</div>""", story=story([
    ("Boucle 1 600 ms", "Le faisceau descend puis remonte sur la pile (courbe d'arrivée, aller-retour) : <code>anim::balayage</code>."),
    ("Boucle 6 s", "Plan arrière : les lignes de fichiers défilent lentement vers le haut (parallaxe, 32 px/s)."),
    ("Boucle 900 ms", "Barre : rayures qui défilent, tête laiton qui pulse (1 200 ms)."),
    ("Chaque fichier", "Le compteur et le nom du fichier changent (texte, pas d'animation)."),
    ("Réduite", "Pas de faisceau ni de défilement ; la barre et le compteur avancent."),
    ("Logiciel", "3 couches : lignes (translation), faisceau (rectangle), barre. ≈ 300 × 190 + 900 × 24 px par trame."),
]))

# 3. Verdict sain --------------------------------------------------------------------------
A["AnimSain"] = dict(h=620, sous="Le bouclier se tourne vers vous, deux ondes, le panneau se pose", cyc="3600ms", css="""
.bouclier { --cote: 200px; left: 50%; margin-left: -100px; top: 6px; animation: bq-images var(--cyc) steps(14, jump-none) infinite, bq-echelle var(--cyc) linear infinite; transform-origin: 50% 55%; }
@keyframes bq-images { 0% { background-position: 0 0; } 11.7%, 100% { background-position: calc(var(--cote) * (1 - var(--n))) 0; } }
@keyframes bq-echelle { 0% { transform: scale(.6); } 8% { transform: scale(.95); } 13% { transform: scale(1.08); } 20%, 100% { transform: scale(1); } }
.onde { position: absolute; left: 50%; top: 110px; width: 150px; height: 150px; margin: -75px 0 0 -75px; border-radius: 50%; border: 6px solid var(--sain); animation: onde var(--cyc) var(--courbe-sortie) infinite; }
.onde.b { animation-delay: 280ms; }
@keyframes onde { 0%, 11% { transform: scale(.7); border-color: transparent; } 12% { transform: scale(.7); border-color: var(--sain); } 26% { border-color: var(--sain-fond); } 34%, 100% { transform: scale(1.7); border-color: transparent; } }
.panneau { position: absolute; left: 70px; right: 70px; bottom: 16px; padding: 12px 20px; animation: pose var(--cyc) var(--courbe-arrivee) infinite; }
.panneau .b-verdict__titre { font-size: 30px; line-height: 34px; }
@keyframes pose { 0%, 16.7% { transform: translateY(24px); visibility: hidden; } 16.8% { visibility: visible; } 25%, 100% { transform: none; visibility: visible; } }
""", reduit=fin(".anim:has(.reduire:checked) .bouclier", "") + """
.anim:has(.reduire:checked) .onde { display: none; }
""", scene="""    <div class="onde"></div><div class="onde b"></div>
    <div class="b-sprite s-bouclier bouclier"></div>
    <div class="panneau b-verdict b-verdict--sain"><div><p class="b-verdict__titre">Clé saine</p><p class="b-verdict__texte">1 038 fichiers peuvent être copiés.</p></div></div>""", story=story([
    ("0 – 420 ms", "Le bouclier pivote de la tranche vers la face (bande <code>bouclier</code>, 14 images) et grandit de 60 % à 108 % puis 100 % : <code>anim::echelle_bouclier</code>."),
    ("430 – 1 220 ms", "Deux ondes pleines s'élargissent derrière lui (×0,7 → ×1,7), décalées de 280 ms, et s'éteignent par paliers de couleur."),
    ("600 – 900 ms", "Le panneau « Clé saine » monte de 24 px et se pose (niveau 3)."),
    ("Ensuite", "Tout est fixe. Le bouton « Choisir la clé de sortie » est actif dès 600 ms."),
    ("Réduite", "Bouclier de face et panneau affichés d'emblée, sans onde."),
    ("Logiciel", "Ondes = anneaux SVG de 3 tailles pré-tramées, couleur changée par palier (pas de transparence). ≈ 360 × 300 px par trame pendant 1,2 s."),
]))

# 4. Verdict bloqué ------------------------------------------------------------------------
A["AnimBloque"] = dict(h=620, sous="La herse tombe, la porte tremble, le panneau descend", cyc="3600ms", css="""
.emb { --cote: 220px; left: 50%; margin-left: -110px; top: -6px; animation: herse var(--cyc) steps(16, jump-none) infinite, secousse var(--cyc) linear infinite; }
@keyframes herse { 0% { background-position: 0 0; } 15%, 100% { background-position: calc(var(--cote) * (1 - var(--n))) 0; } }
@keyframes secousse { 0%, 15% { transform: none; } 17% { transform: translateX(-4px); } 19% { transform: translateX(3.2px); } 21% { transform: translateX(-2.2px); } 23% { transform: translateX(1.2px); } 25% { transform: translateX(-.5px); } 27%, 100% { transform: none; } }
.panneau { position: absolute; left: 70px; right: 70px; bottom: 16px; padding: 12px 20px; animation: tombe var(--cyc) var(--courbe-arrivee) infinite; }
.panneau .b-verdict__titre { font-size: 30px; line-height: 34px; }
.panneau .b-pastille { width: 56px; height: 56px; }
@keyframes tombe { 0%, 16.6% { transform: translateY(-24px); visibility: hidden; } 16.7% { visibility: visible; } 25%, 100% { transform: none; visibility: visible; } }
""", reduit=fin(".anim:has(.reduire:checked) .emb", ""), scene="""    <div class="b-sprite s-embleme-herse emb"></div>
    <div class="panneau b-verdict b-verdict--bloque"><span class="b-pastille"><svg viewBox="0 0 24 24"><path d="m15 9-6 6"/><path d="M2.586 16.726A2 2 0 0 1 2 15.312V8.688a2 2 0 0 1 .586-1.414l4.688-4.688A2 2 0 0 1 8.688 2h6.624a2 2 0 0 1 1.414.586l4.688 4.688A2 2 0 0 1 22 8.688v6.624a2 2 0 0 1-.586 1.414l-4.688 4.688a2 2 0 0 1-1.414.586H8.688a2 2 0 0 1-1.414-.586z"/><path d="m9 9 6 6"/></svg></span><div><p class="b-verdict__titre">2 fichiers bloqués</p><p class="b-verdict__texte">Menace détectée. Ils ne seront pas copiés.</p></div></div>""", story=story([
    ("0 – 540 ms", "La herse tombe (bande <code>embleme-herse</code>, 16 images, courbe lourde) : <code>anim::herse</code>."),
    ("540 – 970 ms", "L'emblème seul tremble : ±4 px amorti, 3 allers-retours. L'écran ne bouge pas."),
    ("600 – 900 ms", "Le panneau « N fichiers bloqués » descend de 24 px (octogone, rouge, mot)."),
    ("Ensuite", "Herse fermée, fixe. Pas de clignotement ni de son : le verdict est un fait, pas une alarme."),
    ("Réduite", "Herse fermée et panneau affichés d'emblée."),
    ("Logiciel", "1 image + 1 translation ; ≈ 220 × 220 px par trame pendant 1 s, puis rien."),
]))

# 5. Blanchiment ---------------------------------------------------------------------------
A["AnimBlanchiment"] = dict(h=600, sous="Une lame de laiton descend et révèle la clé blanchie", cyc="3000ms", css="""
.cle, .blanche { --cote: 220px; left: 50%; margin-left: -110px; top: 0; }
.blanche { animation: revele var(--cyc) steps(6, jump-end) infinite; }
@keyframes revele { from { clip-path: inset(0 0 calc(100% - 66px) 0); } to { clip-path: inset(0 0 calc(100% - 156px) 0); } }
.lame { position: absolute; left: 50%; margin-left: -90px; width: 180px; top: 63px; height: 6px; border-radius: 3px; background: linear-gradient(180deg, var(--laiton-clair), var(--laiton)); box-shadow: 0 2px 0 var(--laiton-fonce); animation: lame var(--cyc) steps(6, jump-end) infinite; }
@keyframes lame { from { transform: translateY(0); } to { transform: translateY(90px); } }
.barre { position: absolute; left: 60px; right: 60px; bottom: 54px; }
.msg { bottom: 4px; font-size: 24px; }
""", reduit="""
.anim:has(.reduire:checked) .lame { display: none; }
.anim:has(.reduire:checked) .blanche { clip-path: inset(0 0 calc(100% - 120px) 0); }
""", scene="""    <div class="b-sprite s-cle cle fixe" style="background-position: calc(220px * -15) 0"></div>
    <div class="b-sprite s-cle-blanche blanche"></div>
    <div class="lame"></div>
    <div class="barre"><div class="b-barre"><div class="b-barre__rempli" style="--p:60"></div></div></div>
    <div class="msg">Blanchiment en cours. Ne retirez pas la clé.</div>""", story=story([
    ("Par palier", "La lame laiton descend par 6 paliers (un par sixième du travail réel, pas du temps) sur la clé."),
    ("Derrière la lame", "La clé blanchie (bande <code>cle-blanche</code>) apparaît à travers une fenêtre qui grandit : ce qui est effacé change de matière."),
    ("Barre", "Progression réelle (octets écrits), vitesse et temps restant : <code>mesure.rs</code>."),
    ("Fin", "La lame disparaît, la clé est blanche, « Blanchiment terminé » ; puis réécriture des fichiers sains (AnimAnalyse)."),
    ("Réduite", "Pas de lame : la fenêtre suit la progression sans paliers animés."),
    ("Logiciel", "2 images fixes + 1 fenêtre de découpage (déjà dans dessin.rs) + 1 rectangle. Redessin seulement au changement de palier."),
]))

# 6. Gravure de disque ---------------------------------------------------------------------
A["AnimGravure"] = dict(h=600, sous="Le disque tourne, le laser avance, l'anneau gravé grandit", cyc="6000ms", css="""
@property --r { syntax: "<percentage>"; inherits: false; initial-value: 36%; }
.disque { --cote: 240px; left: 50%; margin-left: -120px; top: -20px; --d: 600ms; --iter: infinite; }
.grave { position: absolute; left: 50%; top: 50px; width: 202px; height: 93px; margin-left: -101px; border-radius: 50%; background: radial-gradient(closest-side, transparent 36%, color-mix(in srgb, var(--analyse-fonce) 55%, transparent) 36%, color-mix(in srgb, var(--analyse-fonce) 55%, transparent) var(--r), transparent var(--r)); animation: grave var(--cyc) linear infinite; }
@keyframes grave { from { --r: 37%; } to { --r: 97%; } }
.laser { position: absolute; top: 88px; left: 50%; width: 12px; height: 34px; margin-left: 30px; border-radius: 3px; background: linear-gradient(180deg, var(--encre-haut), var(--encre-bas)); box-shadow: 0 3px 0 var(--laiton-fonce); animation: laser var(--cyc) linear infinite; }
.laser::after { content: ""; position: absolute; left: 4px; top: -8px; width: 4px; height: 8px; background: var(--analyse); }
@keyframes laser { from { transform: translateX(6px); } to { transform: translateX(62px); } }
.barre { position: absolute; left: 60px; right: 60px; bottom: 54px; }
.msg { bottom: 4px; font-size: 24px; }
""", reduit="""
.anim:has(.reduire:checked) .disque { background-position: 0 0; }
.anim:has(.reduire:checked) .grave { --r: 70%; }
.anim:has(.reduire:checked) .laser { transform: translateX(40px); }
""", scene="""    <div class="b-sprite s-disque disque"></div>
    <div class="grave"></div>
    <div class="laser"></div>
    <div class="barre"><div class="b-barre"><div class="b-barre__rempli" style="--p:55"></div></div></div>
    <div class="msg">Gravure en cours · 352 Mo / 640 Mo</div>""", story=story([
    ("Boucle 600 ms", "Le disque tourne : bande <code>disque</code>, 18 images = un demi-tour (les reflets sont symétriques)."),
    ("Avancement réel", "L'anneau gravé (plus sombre) s'élargit du centre vers le bord, et la tête laser le suit, à la vitesse de la gravure."),
    ("Barre", "Mo gravés / total, vitesse, temps restant."),
    ("Fin", "Le disque s'arrête sur l'image 0, anneau plein ; « Gravure terminée. Le tiroir va s'ouvrir. »"),
    ("Réduite", "Disque immobile ; l'anneau et la tête suivent la progression sans tourner."),
    ("Logiciel", "1 image + 1 anneau (2 ellipses pleines) + 1 rectangle ; ≈ 240 × 160 px par trame."),
]))

# 7. Erreur --------------------------------------------------------------------------------
A["AnimErreur"] = dict(h=580, sous="La clé tremble, un triangle explique", cyc="3000ms", css="""
.cle { --cote: 200px; left: 50%; margin-left: -130px; top: 20px; animation: secoue var(--cyc) linear infinite; }
@keyframes secoue { 0%, 8% { transform: none; } 10% { transform: translateX(-6px); } 12% { transform: translateX(6px); } 14% { transform: translateX(-5px); } 16% { transform: translateX(5px); } 18% { transform: translateX(-3px); } 20% { transform: translateX(2px); } 22%, 100% { transform: none; } }
.tri { position: absolute; left: 50%; top: 40px; margin-left: 50px; --c: var(--alerte); --fonce: var(--alerte-fonce); animation: sceau var(--cyc) var(--courbe-ressort) infinite; }
@keyframes sceau { 0%, 20% { transform: scale(0); } 30%, 100% { transform: scale(1); } }
.msg { bottom: 34px; font-size: 28px; }
""", reduit="", scene="""    <div class="b-sprite s-cle cle fixe" style="background-position: calc(200px * -15) 0"></div>
    <span class="b-pastille tri"><svg viewBox="0 0 24 24"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg></span>
    <div class="msg">Cette clé n'est pas lisible.</div>
    <div class="sous">Retirez-la et essayez une autre clé.</div>""", story=story([
    ("300 – 660 ms", "La clé tremble 3 fois (±6 px amorti) : « non » de la tête, pas une alarme."),
    ("600 – 900 ms", "Le triangle d'alerte apparaît (0 → 115 % → 100 %) : <code>anim::echelle_sceau</code>."),
    ("Texte", "Ce qui s'est passé, puis quoi faire. Jamais de code d'erreur seul (il va dans le journal)."),
    ("Couleur", "Alerte (orange), pas menace : une clé illisible n'est pas une menace."),
    ("Réduite", "Clé immobile, triangle affiché."),
    ("Logiciel", "1 image + translation, 1 pastille mise à l'échelle ; 600 ms en tout."),
]))

# 8. Attente du serveur (v2) ---------------------------------------------------------------
A["AnimAttenteServeur"] = dict(h=600, sous="v2 en ligne : connexion, délai de grâce", cyc="1200ms", css="""
.emb { --cote: 180px; left: 50%; margin-left: -90px; top: -18px; }
.cren { position: absolute; left: 50%; top: 30px; margin-left: 100px; display: grid; gap: 6px; }
.cren i { display: block; width: 14px; height: 22px; border-radius: 2px; background: var(--surface-creuse); box-shadow: inset 0 1px 2px var(--ombre-interne); animation: allume var(--cyc) steps(1, jump-end) infinite; }
.cren i:nth-child(2) { animation-delay: 400ms; } .cren i:nth-child(1) { animation-delay: 800ms; }
@keyframes allume { 0%, 33% { background: var(--analyse); box-shadow: 0 2px 0 var(--analyse-fonce); } 34%, 100% { background: var(--surface-creuse); box-shadow: inset 0 1px 2px var(--ombre-interne); } }
.grace { position: absolute; left: 50%; top: 178px; margin-left: -170px; width: 340px; }
.msg { bottom: 26px; font-size: 26px; }
""", reduit="""
.anim:has(.reduire:checked) .cren i { background: var(--analyse); box-shadow: 0 2px 0 var(--analyse-fonce); }
""", scene="""    <div class="b-sprite s-embleme-herse emb fixe"></div>
    <div class="cren"><i></i><i></i><i></i></div>
    <div class="grace"><div class="b-barre"><div class="b-barre__rempli" style="--p:84"></div></div></div>
    <div class="msg">Connexion au serveur de gestion…</div>
    <div class="sous b-mono">Délai de grâce : 4 min 12 s</div>""", story=story([
    ("Boucle 1 200 ms", "Trois créneaux s'allument de bas en haut, un toutes les 400 ms : signal qui cherche le serveur."),
    ("Délai de grâce", "Barre qui se VIDE (5 min par défaut, plancher signé) avec le temps restant écrit."),
    ("Retour du serveur", "Créneaux fixes allumés 300 ms, puis retour à l'accueil (glissement d'écran)."),
    ("Délai écoulé", "« Borne hors service : serveur de gestion injoignable » ; herse fermée, fixe, aucune boucle."),
    ("Réduite", "Créneaux allumés fixes ; le temps restant continue de décompter."),
    ("Logiciel", "3 rectangles changent de couleur 3 fois par seconde : redessin quasi nul (≈ 14 × 80 px)."),
]))

for nom, d in A.items():
    (COMP / nom).mkdir(exist_ok=True)
    (COMP / nom / "preview.html").write_text(TETE.format(**d), encoding="utf-8")
    print(nom)
