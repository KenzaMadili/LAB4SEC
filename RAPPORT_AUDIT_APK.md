# 📱 Rapport d'Audit de Sécurité — APK Android
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
| **Analyste** | Étudiant — Lab Sécurité Mobile |
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
```java
public static boolean a(String str) {
    byte[] bArr;
    try {
        // Clé AES hardcodée en hexadécimal
        bArr = sg.vantagepoint.a.a.a(
            b("8d127684cbc37c17616d806cf50473cc"),  // ← CLÉ EN CLAIR
            Base64.decode("5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=", 0) // ← DONNÉES
        );
    } catch (Exception e) {
        Log.d("CodeCheck", "AES error:" + e.getMessage()); // ← LOG SENSIBLE
        bArr = bArr2;
    }
    return str.equals(new String(bArr));
}
```

**Exploitation (PowerShell) :**
```powershell
$key = [byte[]] @(0x8d,0x12,0x76,0x84,0xcb,0xc3,0x7c,0x17,0x61,0x6d,0x80,0x6c,0xf5,0x04,0x73,0xcc)
$encrypted = [Convert]::FromBase64String("5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=")
$aes = [System.Security.Cryptography.Aes]::Create()
$aes.Mode = [System.Security.Cryptography.CipherMode]::ECB
$aes.Key = $key
$decryptor = $aes.CreateDecryptor()
$result = $decryptor.TransformFinalBlock($encrypted, 0, $encrypted.Length)
[System.Text.Encoding]::UTF8.GetString($result)
# Résultat : "I want to believe"
```

**✅ Remédiation :**
- Ne jamais stocker de clés cryptographiques dans le code source
- Utiliser **Android Keystore System** pour stocker les clés de façon sécurisée
- Effectuer la vérification côté serveur via une API sécurisée (HTTPS + authentification)
- Utiliser un mode AES avec IV aléatoire (CBC ou GCM) au lieu de ECB

---

### Constat #2 — Détection Root Statique et Contournable 🟠 MOYEN

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
- [x] Hash SHA-256 noté pour traçabilité
- [x] Structure de l'APK identifiée
- [x] Provenance documentée (OWASP MASTG)
- [x] AndroidManifest.xml analysé
- [x] Code source exploré avec JADX GUI
- [x] DEX converti en JAR avec dex2jar
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
