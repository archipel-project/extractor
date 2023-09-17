package org.archipel.utils.asm;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.Method;
import org.objectweb.asm.tree.*;

import java.io.InputStream;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

public final class ASMUtils {
    private static final Map<Integer, String> OPCODES = Arrays.stream(Opcodes.class.getFields())
            .dropWhile(f -> !f.getName().equals("NOP"))
            .collect(Collectors.toMap(
                    f -> {
                        try {
                            return f.getInt(null);
                        } catch (IllegalAccessException e) {
                            throw new RuntimeException(e);
                        }
                    }, Field::getName
            ));

    public static InputStream loadClass(Class<?> cl) {
        return ClassLoader.getSystemResourceAsStream(cl.getName().replace('.', '/') + ".class");
    }

    public static boolean sameMethod(MethodNode mn, Method m) {
        return mn.name.equals(m.getName()) && mn.desc.equals(m.getDescriptor());
    }

    public static Method getMethod(Class<?> cl, String name, Class<?>... params) {
        try {
            return Method.getMethod(cl.getMethod(name, params));
        } catch (NoSuchMethodException e) {
            throw new RuntimeException(e);
        }
    }

    public static String getOpcodeString(int op) {
        return OPCODES.get(op);
    }

    public static String getInsnAsString(AbstractInsnNode insn) {
        if (insn instanceof LabelNode)
            return "LABEL";
        if (insn instanceof LineNumberNode)
            return "LINE";
        if(insn instanceof FrameNode)
            return "FRAME";
        if (insn != null)
            return getOpcodeString(insn.getOpcode());
        else
            return "null";
    }

    public static String disassemble(AbstractInsnNode insn) {
        var str = new StringBuilder(getInsnAsString(insn)).append(' ');

        if (insn instanceof LabelNode l)
            str.append(l.getLabel().toString());

        if (insn instanceof VarInsnNode v)
            str.append(v.var);

        if (insn instanceof FieldInsnNode f)
            str.append(String.format("%s : %s", f.name, f.desc));

        if(insn instanceof LineNumberNode l)
            str.append(l.line);

        if (insn instanceof MethodInsnNode m)
            str.append(String.format("%s %s", m.name, m.desc));

        if(insn instanceof TypeInsnNode t)
            str.append(t.desc);

        if(insn instanceof IntInsnNode i)
            str.append(i.operand);

        if(insn instanceof JumpInsnNode j)
            str.append(j.label.getLabel().toString());

        if(insn instanceof FrameNode f)
        {
            final var type = f.type;
            str.append(type == -1 ? "NEW" : type == 0 ? "FULL" : "OTHER (%d)".formatted(type))
                    .append(" ")
                    .append(f.local)
                    .append(" ")
                    .append(f.stack);
        }

        return str.toString();
    }
}
