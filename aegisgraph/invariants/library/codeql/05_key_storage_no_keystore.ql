/**
 * @id aegisgraph/inv-05-key-storage-no-keystore
 * @name InvariantCheck INV-05: Private keys persisted outside Android Keystore
 * @description Private cryptographic key material (KeyPair.getPrivate,
 *              SecretKeySpec, libsodium privateKeyBytes, identity/device
 *              key generation outputs) flowing into SharedPreferences,
 *              plain java.io.File / FileOutputStream writes, or unencrypted
 *              SQLite columns rather than through the Android Keystore
 *              (android.security.keystore.KeyGenParameterSpec) or
 *              androidx.security.crypto (EncryptedFile,
 *              EncryptedSharedPreferences) wrappers. This is the
 *              recoverable-on-disk private-key class.
 * @kind path-problem
 * @problem.severity error
 * @precision medium
 * @id-mapping INV-05
 * @tags security
 *       cryptography
 *       privacy
 *       aegisgraph-invariantcheck
 *       mastg-storage-1
 *       ssdf-pw-6-1
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import KeyStorageNoKeystoreFlow::PathGraph

/**
 * Sources: private-key material producers.
 *
 * The shapes we recognize:
 *   * java.security.KeyPair.getPrivate() — JCE private key extraction.
 *   * javax.crypto.spec.SecretKeySpec construction — raw symmetric key.
 *   * org.signal / org.matrix / com.goterl.lazysodium private-key getters.
 *   * Identity-key generation methods named *generateIdentityKey*,
 *     *createPreKey*, *generateDeviceKey*, *generateSenderKey*.
 */
class PrivateKeyMaterialSource extends DataFlow::Node {
  PrivateKeyMaterialSource() {
    // JCE: KeyPair.getPrivate() returns a PrivateKey.
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("java.security", "KeyPair") and
      mc.getMethod().hasName("getPrivate") and
      this.asExpr() = mc
    )
    or
    // javax.crypto.spec.SecretKeySpec(byte[], String) — first arg is raw key bytes.
    exists(ConstructorCall cc |
      cc.getConstructedType().hasQualifiedName("javax.crypto.spec", "SecretKeySpec") and
      this.asExpr() = cc
    )
    or
    // Signal / libsignal / libsodium / Olm name-based getters returning raw key bytes.
    exists(MethodCall mc |
      mc.getMethod()
          .hasName([
            "getPrivateKey", "getPrivateKeyBytes", "privateKeyBytes",
            "getIdentityKeyPair", "getSenderKeyPrivate", "getPreKeyPrivate",
            "getDeviceKeyPrivate", "getMlsLeafKeyPrivate",
            "serializePrivateKey", "getSeed"
          ]) and
      this.asExpr() = mc
    )
    or
    // Generation methods that return raw key material.
    exists(MethodCall mc |
      mc.getMethod()
          .getName()
          .regexpMatch("(?i).*generate(Identity|Device|Sender|Pre|Leaf|Mac|Encryption)Key.*") and
      this.asExpr() = mc
    )
  }
}

/**
 * Sinks: persistence APIs that write to non-keystore storage.
 *
 * We capture three families:
 *   * SharedPreferences.Editor.putString / putStringSet / putByteArray
 *     (where the SharedPreferences instance is NOT an
 *     EncryptedSharedPreferences — barrier handles the encrypted case).
 *   * java.io.FileOutputStream / OutputStream.write / java.io.File.write.
 *   * java.nio.file.Files.write / Files.writeString.
 */
class UnprotectedKeyStorageSink extends DataFlow::Node {
  UnprotectedKeyStorageSink() {
    // SharedPreferences.Editor putters — the value (2nd arg) is the sink.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .hasQualifiedName("android.content", "SharedPreferences$Editor") and
      mc.getMethod()
          .hasName(["putString", "putStringSet", "putByteArray"]) and
      this.asExpr() = mc.getArgument(1)
    )
    or
    // FileOutputStream.write(byte[]) — sink is the bytes arg.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .hasQualifiedName("java.io", "FileOutputStream") and
      mc.getMethod().hasName("write") and
      this.asExpr() = mc.getArgument(0)
    )
    or
    // OutputStream.write where the qualifier is a FileOutputStream-derived
    // stream (covers BufferedOutputStream wrapping FileOutputStream).
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().getName().regexpMatch(".*OutputStream") and
      mc.getMethod().hasName("write") and
      mc.getQualifier().getType().(RefType).getName().regexpMatch(".*File.*OutputStream") and
      this.asExpr() = mc.getArgument(0)
    )
    or
    // java.nio.file.Files.write / Files.writeString.
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
      mc.getMethod().hasName(["write", "writeString"]) and
      this.asExpr() = mc.getArgument(1)
    )
    or
    // androidx.datastore Preferences.edit { putString(...) } — the lambda's
    // putString argument is the sink. We name-match the method.
    exists(MethodCall mc |
      mc.getMethod()
          .getName()
          .regexpMatch("(?i)put(String|Bytes|Value)") and
      mc.getMethod()
          .getDeclaringType()
          .getName()
          .regexpMatch(".*Preferences.*|.*Datastore.*") and
      not mc.getMethod()
          .getDeclaringType()
          .getName()
          .regexpMatch(".*Encrypted.*|.*Keystore.*|.*KeyStore.*") and
      this.asExpr() = mc.getArgument(mc.getNumArgument() - 1)
    )
  }
}

/**
 * Barriers: Android Keystore-rooted storage and EncryptedFile /
 * EncryptedSharedPreferences wrappers.
 *
 * A key flowing through any of these is considered safely persisted.
 */
class KeystoreOrEncryptedStorageBarrier extends DataFlow::Node {
  KeystoreOrEncryptedStorageBarrier() {
    // android.security.keystore.KeyGenParameterSpec.Builder — once a key
    // is loaded into a Keystore-aliased KeyStore, subsequent uses are
    // safe.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .hasQualifiedName("android.security.keystore",
                            ["KeyGenParameterSpec$Builder",
                             "KeyGenParameterSpec",
                             "KeyProperties"]) and
      this.asExpr() = [mc, mc.getAnArgument()]
    )
    or
    // androidx.security.crypto.EncryptedFile / EncryptedSharedPreferences.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .hasQualifiedName("androidx.security.crypto",
                            ["EncryptedFile",
                             "EncryptedFile$Builder",
                             "EncryptedSharedPreferences",
                             "MasterKey",
                             "MasterKey$Builder",
                             "MasterKeys"]) and
      this.asExpr() = [mc, mc.getAnArgument()]
    )
    or
    // java.security.KeyStore.setKeyEntry / setEntry under the Android
    // Keystore provider.
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("java.security", "KeyStore") and
      mc.getMethod().hasName(["setKeyEntry", "setEntry"]) and
      this.asExpr() = mc.getAnArgument()
    )
    or
    // Tink AndroidKeysetManager.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .getName()
          .regexpMatch(".*AndroidKeyset.*|.*KeysetHandle.*") and
      this.asExpr() = [mc, mc.getAnArgument()]
    )
  }
}

/**
 * Configuration: taint flow from private-key sources to unprotected-
 * storage sinks, with Keystore-rooted barriers as sanitizers.
 */
module KeyStorageNoKeystoreConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof PrivateKeyMaterialSource }

  predicate isSink(DataFlow::Node snk) { snk instanceof UnprotectedKeyStorageSink }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof KeystoreOrEncryptedStorageBarrier
  }
}

module KeyStorageNoKeystoreFlow = TaintTracking::Global<KeyStorageNoKeystoreConfig>;

from KeyStorageNoKeystoreFlow::PathNode source, KeyStorageNoKeystoreFlow::PathNode sink
where KeyStorageNoKeystoreFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "INV-05: Private key material from $@ persisted to non-keystore storage without traversing Android Keystore / EncryptedFile barrier.",
  source.getNode(), "this source"
