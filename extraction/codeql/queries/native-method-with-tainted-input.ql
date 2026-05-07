/**
 * @id aegisgraph/native-method-with-tainted-input
 * @name AegisGraph: Native methods whose params originate from network/IPC
 * @description Methods declared `native` that receive at least one parameter
 *              with a remote source (network buffer, intent extra, IPC
 *              message). These are JNI/native_boundary nodes and feed the
 *              native_boundary path-class.
 * @kind path-problem
 * @problem.severity warning
 * @precision low
 * @tags security
 *       external-input
 *       native-boundary
 *       aegisgraph-sma
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking

/** A native method is one declared with the `native` modifier. */
class NativeMethod extends Method {
  NativeMethod() { this.isNative() }
}

/** A native call: any callsite into a `native` method. */
class NativeCall extends MethodCall {
  NativeCall() { this.getMethod() instanceof NativeMethod }
}

/**
 * Taint configuration: source = any RemoteFlowSource (network/IPC), sink =
 * any argument to a native call.
 */
module NativeTaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) {
    exists(NativeCall nc, int i |
      sink.asExpr() = nc.getArgument(i)
    )
  }
}

module NativeTaintFlow = TaintTracking::Global<NativeTaintConfig>;

import NativeTaintFlow::PathGraph

from NativeTaintFlow::PathNode source, NativeTaintFlow::PathNode sink, NativeCall nc
where
  NativeTaintFlow::flowPath(source, sink) and
  sink.getNode().asExpr() = nc.getAnArgument()
select nc, source, sink,
  "Native method '" + nc.getMethod().getQualifiedName() +
    "' receives data flowing from a remote source."
