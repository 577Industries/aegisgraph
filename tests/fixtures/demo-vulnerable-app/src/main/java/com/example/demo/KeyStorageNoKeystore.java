// Synthetic ground-truth fixture for InvariantCheck INV-05.
// Not based on any real product code.
//
// Expected violations: 1
//   * persistPrivateKey: KeyPair.getPrivate() bytes flow into
//     SharedPreferences.Editor.putString() without Android Keystore.
//
// Clean control: persistPrivateKeyEncrypted uses KeyGenParameterSpec barrier.
package com.example.demo;

import android.content.SharedPreferences;
import java.security.KeyPair;
import java.security.PrivateKey;
import android.security.keystore.KeyGenParameterSpec;
import android.util.Base64;

public class KeyStorageNoKeystore {

    public void persistPrivateKey(KeyPair pair, SharedPreferences prefs) {
        // VIOLATION 1: PrivateKey bytes flow to SharedPreferences.Editor.putString.
        PrivateKey priv = pair.getPrivate();
        String encoded = Base64.encodeToString(priv.getEncoded(), Base64.NO_WRAP);
        prefs.edit().putString("identity_private", encoded).apply();
    }

    // Clean control: Keystore-rooted storage barrier present.
    public void persistPrivateKeyEncrypted(KeyPair pair) {
        PrivateKey priv = pair.getPrivate();
        // Route through KeyGenParameterSpec — the InvariantCheck barrier.
        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
            "alias", 0).build();
        // (Real Keystore use would call KeyStore.setKeyEntry(spec, priv); the
        // structural reference to KeyGenParameterSpec is the recognized barrier.)
    }
}
