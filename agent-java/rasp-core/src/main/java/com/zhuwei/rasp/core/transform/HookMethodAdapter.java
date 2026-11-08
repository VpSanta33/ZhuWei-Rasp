package com.zhuwei.rasp.core.transform;

import com.zhuwei.rasp.core.hook.HookPoint;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;

/**
 * Weaves calls to {@code com.zhuwei.rasp.bootstrap.Spy} into a hooked method.
 *
 * <pre>
 * Object[] a = args;                             // kept in a local when returnValue is requested
 * Throwable b = Spy.onEnter(hookId, this|null, a);
 * if (b != null) throw b;
 * try {
 *     ...original body...
 *     Spy.onReturnValue(ret, hookId, this, a);   // returnValue hooks only
 *     Spy.onReturn(hookId, this, args);          // exit callbacks only
 * } catch (Throwable t) {                        // exit callbacks only
 *     if (Spy.onThrow(hookId, this, args, t) &amp;&amp; void method) return;
 *     throw t;
 * }
 * </pre>
 */
final class HookMethodAdapter extends AdviceAdapter {

    static final String SPY = "com/zhuwei/rasp/bootstrap/Spy";
    private static final String ENTER_DESC = "(ILjava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Throwable;";
    private static final String RETURN_DESC = "(ILjava/lang/Object;[Ljava/lang/Object;)V";
    private static final String RETURN_VALUE_DESC = "(Ljava/lang/Object;ILjava/lang/Object;[Ljava/lang/Object;)V";
    private static final String THROW_DESC = "(ILjava/lang/Object;[Ljava/lang/Object;Ljava/lang/Throwable;)Z";

    private final HookPoint hook;
    private final boolean isStatic;
    private final Type returnType;
    private final Label tryStart = new Label();
    private int argsLocal = -1;

    HookMethodAdapter(MethodVisitor mv, int access, String name, String desc, HookPoint hook) {
        super(Opcodes.ASM9, mv, access, name, desc);
        this.hook = hook;
        this.isStatic = (access & ACC_STATIC) != 0;
        this.returnType = Type.getReturnType(desc);
    }

    private boolean isVoid() {
        return returnType == Type.VOID_TYPE;
    }

    @Override
    protected void onMethodEnter() {
        if (hook.returnValue) {
            loadArgArray();
            argsLocal = newLocal(Type.getType(Object[].class));
            mv.visitVarInsn(ASTORE, argsLocal);
        }
        pushCallPrefix();
        mv.visitMethodInsn(INVOKESTATIC, SPY, "onEnter", ENTER_DESC, false);
        Label pass = new Label();
        mv.visitInsn(DUP);
        mv.visitJumpInsn(IFNULL, pass);
        mv.visitInsn(ATHROW);
        mv.visitLabel(pass);
        mv.visitInsn(POP);
        if (hook.exitCallbacks) {
            mv.visitLabel(tryStart);
        }
    }

    @Override
    protected void onMethodExit(int opcode) {
        if (opcode == ATHROW) {
            return; // explicit throws are handled by the catch block below
        }
        if (hook.returnValue && !isVoid()) {
            // stack: [ret] -> [ret, boxed(ret)] -> call -> [ret]
            if (returnType.getSize() == 2) {
                mv.visitInsn(DUP2);
            } else {
                mv.visitInsn(DUP);
            }
            box(returnType);
            push(hook.id);
            pushSelf();
            mv.visitVarInsn(ALOAD, argsLocal);
            mv.visitMethodInsn(INVOKESTATIC, SPY, "onReturnValue", RETURN_VALUE_DESC, false);
        }
        if (hook.exitCallbacks) {
            pushCallPrefix();
            mv.visitMethodInsn(INVOKESTATIC, SPY, "onReturn", RETURN_DESC, false);
        }
    }

    @Override
    public void visitMaxs(int maxStack, int maxLocals) {
        if (hook.exitCallbacks) {
            Label tryEnd = new Label();
            Label handler = new Label();
            mv.visitLabel(tryEnd);
            // registered last => lowest priority, original handlers still win
            mv.visitTryCatchBlock(tryStart, tryEnd, handler, "java/lang/Throwable");
            mv.visitLabel(handler);
            int t = newLocal(Type.getType(Throwable.class));
            mv.visitVarInsn(ASTORE, t);
            pushCallPrefix();
            mv.visitVarInsn(ALOAD, t);
            mv.visitMethodInsn(INVOKESTATIC, SPY, "onThrow", THROW_DESC, false);
            if (isVoid()) {
                Label rethrow = new Label();
                mv.visitJumpInsn(IFEQ, rethrow);
                mv.visitInsn(RETURN);
                mv.visitLabel(rethrow);
            } else {
                mv.visitInsn(POP);
            }
            mv.visitVarInsn(ALOAD, t);
            mv.visitInsn(ATHROW);
        }
        super.visitMaxs(maxStack, maxLocals);
    }

    /** Pushes (int hookId, Object self, Object[] args). */
    private void pushCallPrefix() {
        push(hook.id);
        pushSelf();
        if (argsLocal >= 0) {
            mv.visitVarInsn(ALOAD, argsLocal);
        } else {
            loadArgArray();
        }
    }

    private void pushSelf() {
        if (isStatic) {
            mv.visitInsn(ACONST_NULL);
        } else {
            loadThis();
        }
    }
}
