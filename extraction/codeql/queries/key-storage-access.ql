/**
 * @id aegisgraph/key-storage-access
 * @name AegisGraph: KeyStore / encrypted SharedPreferences / Realm encryption keys
 * @description Methods or call sites that access cryptographic key storage:
 *              `java.security.KeyStore`, AndroidX `EncryptedSharedPreferences`,
 *              Realm-Java `RealmConfiguration.encryptionKey`, MatrixRustSDK
 *              `Olm` / `Megolm` session storage. Output feeds the
 *              crypto_key_lifecycle path-class.
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @tags security
 *       crypto
 *       key-storage
 *       aegisgraph-sma
 */

import java

class KeyStoreApi extends Method {
  KeyStoreApi() {
    this.getDeclaringType().getQualifiedName() = "java.security.KeyStore" or
    this.getDeclaringType().getQualifiedName() = "javax.crypto.KeyGenerator" or
    this.getDeclaringType().getQualifiedName() = "android.security.keystore.KeyGenParameterSpec" or
    this.getDeclaringType().getQualifiedName() = "androidx.security.crypto.EncryptedSharedPreferences" or
    this.getDeclaringType().getQualifiedName() = "androidx.security.crypto.MasterKeys" or
    this.getDeclaringType().getQualifiedName() = "io.realm.RealmConfiguration" and
    this.getName() = "encryptionKey" or
    this.getDeclaringType().getQualifiedName().matches("org.matrix.olm.%") or
    this.getDeclaringType().getQualifiedName().matches("org.matrix.rustcomponents.sdk.%")
  }
}

from MethodCall mc
where mc.getMethod() instanceof KeyStoreApi
select mc,
  "Key-storage access: '" + mc.getMethod().getQualifiedName() +
    "' called from '" + mc.getEnclosingCallable().getQualifiedName() + "'."
