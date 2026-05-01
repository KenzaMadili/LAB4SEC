# 📱 Rapport d'Audit de Sécurité — APK Android (Auteur : MADILI Kenza)
## OWASP UnCrackable Level 1

---

## 📋 Informations Générales

| Champ | Valeur |
|---|---|
| **Application** | OWASP UnCrackable Level 1 |
| **Package** | `owasp.mstg.uncrackable1` |
| **Version** | 1.0 (versionCode: 1) |
| **Provenance** | OWASP Mobile Security Testing Guide (MASTG) — APK de cours |
| **Date d'analyse** | 01/05/2026 |
| **Analyste** | Madili Kenza — Lab Sécurité Mobile |
| **SHA-256** | `1DA8BF57D266109F9A07C01BF7111A1975CE01F190B9D914BCD3AE3DBEF96F21` |
| **Taille** | ~100 KB |
| **minSdkVersion** | 19 (Android 4.4) |
| **targetSdkVersion** | 28 (Android 9) |

---

## 🛠️ Environnement & Outils

| Outil | Version | Usage |
|---|---|---|
| **JADX GUI** | 1.5.0 | Décompilation APK → Java |
| **dex2jar** | 2.4 | Conversion DEX → JAR |
| **JD-GUI** | 1.6.6 | Analyse JAR décompilé |
| **Java** | 25.0.2 | Runtime des outils |
| **OS** | Windows 11 | Environnement d'analyse |

---

## 📦 Structure de l'APK

Vérification : signature `50 4B` (`PK`) confirmée → archive ZIP valide ✅

```
UnCrackable-Level1.apk
├── AndroidManifest.xml       ← Configuration, permissions, composants
├── classes.dex               ← Bytecode Dalvik (code Java compilé)
├── resources.arsc            ← Ressources compilées
├── META-INF/
│   ├── CERT.RSA              ← Certificat de signature
│   ├── CERT.SF               ← Signatures des fichiers
│   └── MANIFEST.MF           ← Manifeste de signature
└── res/
    ├── layout/activity_main.xml
    ├── menu/menu_main.xml
    └── mipmap-*/ic_launcher.png
```

---

## 🔐 Analyse du AndroidManifest.xml

<img width="656" height="358" alt="4" src="https://github.com/user-attachments/assets/fe59785a-01e1-4e28-8c95-d5c04f72f9d9" />

### Permissions déclarées

> ✅ **Aucune permission déclarée** — Surface d'attaque réseau/matérielle nulle.

### Composants exposés

| Composant | Classe | Exporté | Intent Filter |
|---|---|---|---|
| Activity | `sg.vantagepoint.uncrackable1.MainActivity` | Implicite (launcher) | `android.intent.action.MAIN` |

> ✅ Pas de `exported="true"` explicite sur des composants sensibles.

### Flags de configuration

| Attribut | Valeur | Statut |
|---|---|---|
| `android:allowBackup` | `true` | ⚠️ Risque |
| `android:debuggable` | Non défini (false par défaut) | ✅ OK |
| `android:targetSdkVersion` | 28 | ⚠️ Obsolète |

---

## 🔍 Analyse du Code Source (JADX)

### Architecture des classes

```
sg.vantagepoint.uncrackable1/
├── MainActivity.java     ← Activité principale, logique UI
└── a.java                ← Vérification du secret (AES)

sg.vantagepoint.a/
├── a.java                ← Fonction de déchiffrement AES
├── b.java                ← Détection mode debug
└── c.java                ← Détection root (3 méthodes)
```

---

## 🚨 Constats de Sécurité

---

### Constat #1 — Clé AES Hardcodée dans le Code Source 🔴 CRITIQUE

**Classe :** `sg.vantagepoint.uncrackable1.a`  
**Risque :** Critique  
**CWE :** CWE-321 — Use of Hard-coded Cryptographic Key  

**Description :**  
La clé de chiffrement AES et les données chiffrées sont toutes deux présentes en clair dans le code source. N'importe qui disposant d'un décompilateur peut extraire le secret en quelques minutes.

**Code vulnérable :**
<img width="1889" height="948" alt="Capture d&#39;écran 2026-05-01 174548" src="https://github.com/user-attachments/assets/a7abc1e5-505a-4a68-974a-b34775f100ae" />


**Exploitation (PowerShell) :**
<img width="1288" height="467" alt="Capture d&#39;écran 2026-05-01 174636" src="https://github.com/user-attachments/assets/94a9727b-dac9-4d5c-9627-8f7200ef5f97" />


**✅ Remédiation :**
- Ne jamais stocker de clés cryptographiques dans le code source
- Utiliser **Android Keystore System** pour stocker les clés de façon sécurisée
- Effectuer la vérification côté serveur via une API sécurisée (HTTPS + authentification)
- Utiliser un mode AES avec IV aléatoire (CBC ou GCM) au lieu de ECB

---

### Constat #2 — Détection Root Statique et Contournable 🟠 MOYEN

<img width="800" height="494" alt="javadecomp" src="https://github.com/user-attachments/assets/46cb3ce6-de6a-4657-9363-01dede25ca89" />

**Classe :** `sg.vantagepoint.a.c`  
**Risque :** Moyen  
**CWE :** CWE-693 — Protection Mechanism Failure  

**Description :**  
L'application tente de détecter un environnement rooté via 3 méthodes statiques, toutes facilement contournables par un attaquant expérimenté.

**Code analysé :**
```java
// Méthode 1 : cherche "su" dans le PATH
public static boolean a() {
    for (String str : System.getenv("PATH").split(":")) {
        if (new File(str, "su").exists()) return true;
    }
    return false;
}

// Méthode 2 : vérifie Build.TAGS pour "test-keys"
public static boolean b() {
    String str = Build.TAGS;
    return str != null && str.contains("test-keys");
}

// Méthode 3 : liste de chemins Superuser statiques
public static boolean c() {
    for (String str : new String[]{
        "/system/app/Superuser.apk",
        "/system/xbin/daemonsu",
        "/system/etc/init.d/99SuperSUDaemon", ...
    }) {
        if (new File(str).exists()) return true;
    }
    return false;
}
```

**Failles de cette approche :**
- La liste de chemins est **statique et publiquement connue**
- **Magisk** (root invisible) contourne toutes ces vérifications
- **Frida** ou **Xposed** peuvent hooker ces méthodes pour retourner `false`
- Un attaquant peut simplement renommer le binaire `su`

**✅ Remédiation :**
- Utiliser **Google Play Integrity API** (remplaçant de SafetyNet)
- Intégrer une bibliothèque spécialisée comme **RootBeer** ou **TrustKit**
- Combiner plusieurs vérifications dynamiques et les obfusquer
- Effectuer les vérifications côté serveur

---

### Constat #3 — allowBackup Activé + Détection Debug Basique 🟠 MOYEN

**Fichiers :** `AndroidManifest.xml` + `sg.vantagepoint.a.b`  
**Risque :** Moyen  
**CWE :** CWE-530 — Exposure of Backup File to Unauthorized Control Sphere  

**Description :**

**3a — allowBackup="true" :**  
Ce flag permet à `adb backup` d'extraire toutes les données privées de l'application sans nécessiter de root, uniquement avec un accès USB et le mode débogage USB activé.

```bash
# Attaque possible avec accès physique
adb backup -noapk owasp.mstg.uncrackable1
# → Extrait les SharedPreferences, bases SQLite, fichiers internes
```

**3b — Détection debug basique :**
```java
// Vérifie uniquement le flag FLAG_DEBUGGABLE
public static boolean a(Context context) {
    return (context.getApplicationContext().getApplicationInfo().flags & 2) != 0;
}
```
Cette vérification est contournable via Frida en hookant `getApplicationInfo()`.

**✅ Remédiation :**
- Définir `android:allowBackup="false"` dans le manifeste
- Utiliser `android:fullBackupOnly="true"` avec des règles de backup sélectives si nécessaire
- Pour la détection debug : combiner avec une vérification de l'intégrité du certificat et du Play Integrity API

---

## 📊 Comparaison JADX vs JD-GUI
<img width="800" height="494" alt="javadecomp" src="https://github.com/user-attachments/assets/06130fc9-dac7-4e3b-828f-f258323a508f" />

| Critère | JADX GUI | JD-GUI |
|---|---|---|
| **Format d'entrée** | APK direct | JAR (après dex2jar) |
| **Ressources XML** | ✅ Oui (décodées) | ❌ Non |
| **AndroidManifest** | ✅ Lisible | ❌ Non disponible |
| **Navigation** | Arborescence complète | Par packages/classes |
| **Lisibilité** | Très bonne | Bonne |
| **Noms de variables** | Mieux préservés | Parfois altérés |
| **Workflow** | All-in-one | Étape supplémentaire (dex2jar) |
| **Recommandation** | ⭐ Prioritaire | Complémentaire |

> **Conclusion :** JADX est l'outil de référence pour l'analyse APK. JD-GUI reste utile comme second regard sur le bytecode décompilé.

---

## 📈 Résumé des Risques

| # | Constat | Sévérité | Effort d'exploitation | Remédiation |
|---|---|---|---|---|
| 1 | Clé AES hardcodée | 🔴 Critique | Faible (5 min) | Android Keystore + API serveur |
| 2 | Détection root contournable | 🟠 Moyen | Moyen (Magisk/Frida) | Play Integrity API |
| 3 | allowBackup + debug basique | 🟠 Moyen | Faible (adb) | allowBackup=false |

---

## ✅ Checklist Lab

- [x] Dossier de travail créé (`C:\lab-apk\`)
- [x] APK vérifié comme archive ZIP valide (signature `PK`)
      <img width="584" height="124" alt="Capture d’écran 2026-05-01 173614" src="https://github.com/user-attachments/assets/2c550ab5-646b-4e63-8168-4555075545e8" />

- [x] Hash SHA-256 noté pour traçabilité
      <img width="670" height="84" alt="3" src="https://github.com/user-attachments/assets/8a407aaa-a2cc-4f25-bae7-9f78abc45931" />

- [x] Structure de l'APK identifiée
      <img width="657" height="215" alt="2" src="https://github.com/user-attachments/assets/6679be85-99ff-46f2-90e9-2a1774bbd1dd" />

- [x] Provenance documentée (OWASP MASTG)
- [x] AndroidManifest.xml analysé
- [x] Code source exploré avec JADX GUI
- [x] DEX converti en JAR avec dex2jar
      <img width="668" height="119" alt="10" src="https://github.com/user-attachments/assets/a6cd29d6-1709-437d-a51f-1a4f6f9e37eb" />

- [x] JAR analysé avec JD-GUI
- [x] 3 constats de sécurité documentés
- [x] Remédiations proposées pour chaque constat
- [x] Comparaison JADX vs JD-GUI effectuée

---

## 📚 Références

- [OWASP MASTG — Android Crackmes](https://mas.owasp.org/crackmes/Android/)
- [CWE-321 — Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)
- [Android Keystore System](https://developer.android.com/training/articles/keystore)
- [Google Play Integrity API](https://developer.android.com/google/play/integrity)
- [JADX GitHub](https://github.com/skylot/jadx)
- [dex2jar GitHub](https://github.com/pxb1988/dex2jar)

---

*Rapport généré dans le cadre d'un lab pédagogique — APK autorisé (OWASP MASTG)*
