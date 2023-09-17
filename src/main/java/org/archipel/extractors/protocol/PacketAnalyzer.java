package org.archipel.extractors.protocol;

import com.google.gson.JsonObject;
import net.minecraft.network.PacketByteBuf;
import net.minecraft.network.packet.Packet;
import org.archipel.Main;
import org.archipel.utils.asm.ASMUtils;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.Method;
import org.objectweb.asm.tree.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

public final class PacketAnalyzer {
    private static final Method TARGET = ASMUtils.getMethod(Packet.class, "write", PacketByteBuf.class);

    //public static Multimap<String, Pair<String, String>> packetToFieldsMap = ArrayListMultimap.create();

    public static JsonObject analyze(Class<? extends Packet<?>> packet) {
        final JsonObject object = new JsonObject();
        try(var in = ASMUtils.loadClass(packet)) {
            var cr = new ClassReader(in);
            var cn = new ClassNode();

            cr.accept(cn, ClassReader.EXPAND_FRAMES);

            var writeMethod = cn.methods.stream()
                    .filter(m -> ASMUtils.sameMethod(m, TARGET))
                    .findFirst()
                    .orElseThrow();

            /*var inter = new TrackingInterpreter(writeMethodInstruction);
            var a = new CFAnalyser<>(inter);

            a.analyze(Type.getInternalName(packet), writeMethodInstruction);

            var insns = writeMethodInstruction.instructions.toArray();
            var nodes = a.getFrames();*/

            /* for (Frame<SourceValue> node : nodes) {
                if (node instanceof Node<?> n && n.successors.size() > 1) {
                    Main.LOGGER.info(packet.getName() + " needs special process");
                    break;
                }
            } */

            Main.LOGGER.info(packet.getName() + ":");

            final var x = processMethod(writeMethod);
            object.addProperty("packet", packet.getSimpleName()
                    .replace("C2SPacket", "")
                    .replace("S2CPacket", ""));
            final JsonObject struct = new JsonObject();
            for (final PacketValue packetValue : x.struct)
            {
                System.out.println(packetValue.type + " " + packetValue.name);
                if(!struct.has(packetValue.name))
                    struct.addProperty(packetValue.name, packetValue.type);
                else struct.addProperty(packetValue.name + "_" + new Random().nextInt(0xFF), packetValue.type);
                // TODO: better name
            }
            object.addProperty("special", x.special);
            object.add("struct", struct);

            /*for (int i = 0; i < nodes.length; i++)
            {
                //final Node<SourceValue> node = (Node<SourceValue>)nodes[i];
                if (nodes[i] instanceof Node<SourceValue> sourceValueNode)
                {
                    System.out.println("---------------------------------");
                    System.out.println(packet.getName());
                    System.out.println(ASMUtils.disassemble(insns[i]));
                    System.out.println(sourceValueNode);
                    //analyzeFrame(packet, inter, insns[i], sourceValueNode);
                }
            }*/
        } catch (Exception e) {
            Main.LOGGER.error("Failed to analyze " + packet, e);
        }

        return object;
    }

    private static PacketContainer processMethod(MethodNode methodNode) throws Exception
    {
        final var instructions = methodNode.instructions.toArray();

        final List<MethodInsnNode> writeMethods = Arrays.stream(instructions)
                .filter(insn -> insn instanceof MethodInsnNode)
                .map(insn -> (MethodInsnNode)insn)
                .filter(insn -> insn.owner.equals("net/minecraft/network/PacketByteBuf"))
                .filter(insn -> insn.name.startsWith("write"))
                .toList();

        final List<MethodInsnNode> otherWriteMethods = Arrays.stream(instructions)
                .filter(insn -> insn instanceof MethodInsnNode)
                .map(insn -> (MethodInsnNode)insn)
                .filter(insn -> !insn.owner.equals("net/minecraft/network/PacketByteBuf"))
                .filter(insn -> insn.name.startsWith("write"))
                .toList();

        final boolean containsJumps = Arrays.stream(instructions)
                .anyMatch(insn -> insn instanceof JumpInsnNode);

        List<PacketValue> result = new ArrayList<>();

        if(!otherWriteMethods.isEmpty() || containsJumps)
        {
            System.out.println("This packet needs a manual process.");
            return new PacketContainer(true, result);
        }

        boolean special = false;

        for (final MethodInsnNode writeMethodInstruction : writeMethods)
        {
            final var type = writeMethodInstruction.name.substring(5);
            final Type[] args = Type.getArgumentTypes(writeMethodInstruction.desc);
            if(args.length == 1 || writeMethodInstruction.name.equals("writeCollection") ||
                    writeMethodInstruction.name.equals("writeOptional") ||
                    writeMethodInstruction.name.equals("writeNullable") ||
                    writeMethodInstruction.name.equals("writeEnumSet") ||
                    writeMethodInstruction.name.equals("writeMap"))
            {
                final String name = processMethodInstruction(args[0], methodNode, writeMethodInstruction);
                result.add(new PacketValue(type, name));
            }
            else
            {
                // some two args methods manually handled
                if(writeMethodInstruction.name.equals("writeString"))
                {
                    // assume that there is a ICONST_X / SIPUSH X / BIPUSH X before the method call
                    final String name = processMethodInstruction(args[0], methodNode, writeMethodInstruction.getPrevious());
                    result.add(new PacketValue(type, name));
                }
                else if(writeMethodInstruction.name.equals("writeRegistryValue") || writeMethodInstruction.name.equals("writeRegistryEntry"))
                {
                    final String name = processMethodInstruction(args[1], methodNode, writeMethodInstruction);
                    result.add(new PacketValue(type, name));
                }
                else
                {
                    System.out.println("Two args required: " + writeMethodInstruction.name);
                    special = true;
                }
            }
        }

        if(!special)
        {
            for (final PacketValue packetValue : result)
            {
                if(packetValue.name.equals("null"))
                {
                    special = true;
                    break;
                }
            }
        }

        return new PacketContainer(special, result);
    }

    private static String processMethodInstruction(Type arg, MethodNode methodNode, AbstractInsnNode instruction) throws Exception
    {
        final var argInsn = fulfillArg(methodNode.localVariables, instruction, arg);
        String name = "null";
        if(argInsn instanceof FieldInsnNode fieldInsnNode)
            name = fieldInsnNode.name;
        else if(argInsn instanceof VarInsnNode varInsnNode)
            name = methodNode.localVariables.get(varInsnNode.var).name;
        else System.out.println("Erreur ?");

        return name;
    }

    private static AbstractInsnNode fulfillArg(List<LocalVariableNode> localVariablesTable, AbstractInsnNode start, Type toFulfill) throws Exception
    {
        AbstractInsnNode current = start.getPrevious();
        while (current != null)
        {
            if (current instanceof VarInsnNode varInsnNode)
            {
                final var varType = Type.getType(localVariablesTable.get(varInsnNode.var).desc);

                if (checkCompatibility(toFulfill, varType))
                    return current;
            }

            if(current instanceof FieldInsnNode fieldInsnNode)
            {
                final var fieldType = Type.getType(fieldInsnNode.desc);

                if (checkCompatibility(toFulfill, fieldType))
                    return current;
            }

            if(current instanceof MethodInsnNode methodInsnNode)
            {
                final var returnType = Type.getReturnType(methodInsnNode.desc);

                if(returnType.equals(toFulfill))
                    return fulfillArg(localVariablesTable, current, Type.getObjectType(methodInsnNode.owner));

                if(toFulfill.getSort() == Type.OBJECT && returnType.getSort() == Type.OBJECT)
                {
                    final var toFulfillClass = Class.forName(toFulfill.getClassName());
                    if(toFulfillClass.isAssignableFrom(Class.forName(returnType.getClassName())))
                        return fulfillArg(localVariablesTable, current, Type.getObjectType(methodInsnNode.owner));
                    else System.out.println("Erreur ?");
                }
                else System.out.println("Erreur ?");
            }

            current = current.getPrevious();
        }
        System.out.println("Erreur ?");
        return null;
    }

    private static boolean checkCompatibility(Type toFulfill, Type fieldType) throws ClassNotFoundException
    {
        if(fieldType.equals(toFulfill) || ((fieldType.getSort() == Type.BYTE || fieldType.getSort() == Type.SHORT) && toFulfill.getSort() == Type.INT))
            return true;

        if(toFulfill.getSort() == Type.OBJECT && fieldType.getSort() == Type.OBJECT)
        {
            final var toFulfillClass = Class.forName(toFulfill.getClassName());
            if(toFulfillClass.isAssignableFrom(Class.forName(fieldType.getClassName()))) return true;
            else System.out.println("Erreur ?");
        }
        else System.out.println("Erreur ?");
        return false;
    }

    private record PacketContainer(boolean special, List<PacketValue> struct) {}
    private record PacketValue(String type, String name) {}

    /*private static void analyzeFrame(Class<? extends Packet<?>> packet, TrackingInterpreter inter, AbstractInsnNode insn, Node<SourceValue> n) throws AnalyzerException {
        if (insn instanceof MethodInsnNode m) {
            Main.LOGGER.info(m.name + ':');
            // List<Type> argTypes = new ArrayList<>(List.of(Type.getArgumentTypes(m.desc)));
            // Collections.reverse(argTypes);

            FieldInsnNode field = null;
            var bufArg = false;

            for (int i = 0; i < Type.getArgumentTypes(m.desc).length + 1; i++) {
                var stack = n.getStack((n.getStackSize() - 1) - i);

                var fields = inter.fields(stack);
                var locals = inter.locals(stack);

                if (!fields.isEmpty())
                    field = fields.toArray(new FieldInsnNode[0])[0];
                if (fields.size() > 1)
                    throw new AnalyzerException(insn, "invalid number of fields");

                if (!locals.isEmpty())
                    bufArg = locals.toArray(new LocalVariableNode[0])[0].desc.equals(Type.getDescriptor(PacketByteBuf.class));
                if (fields.size() > 1)
                    throw new AnalyzerException(insn, "invalid number of locals");
            }

            if (bufArg) {
                packetToFieldsMap.put(packet.getName(), Pair.of(field != null ? field.name : "null", m.name + m.desc));
            }
        }

        /*
            var hasBranch = false;

            for (int i = 0; i < frms.length; i++) {
                if (frms[i] instanceof Node<?> n && n.successors.size() > 1) {
                    Main.LOGGER.info(i + " " + ASMUtils.disassemble(insns[i]));
                    n.successors.forEach(s -> Main.LOGGER.info("\t" + s + "-> " + ASMUtils.disassemble(insns[s])));
                }
            }

            /* if (hasBranch) {
                for (int i = 0; i < frms.length; i++) {
                    // Main.LOGGER.info("\t" + ASMUtils.disassemble(insns[i]));
                    //analyzeFrame(inter, insns[i], (Node<SourceValue>)frms[i]);
                }
            } */

        /* if (insn instanceof MethodInsnNode m) {
            Main.LOGGER.info(m.name + " " + m.desc);

            for (int i = 0; i < fr.getStackSize(); i++) {
                var v = fr.getStack(i);

                var nF = inter.fields(v).size();
                var nL = inter.locals(v).size();

                if (nF > 1) {
                    Main.LOGGER.info(nF + " fields");
                    inter.fields(v).forEach(f -> Main.LOGGER.info(String.format("%#x %s %s", System.identityHashCode(v), f.name, f.desc)));
                }

                if (nL > 1) {
                    Main.LOGGER.info(nL + " locals");
                    inter.locals(v).forEach(t -> Main.LOGGER.info(String.format("%#x %s", System.identityHashCode(v), t.name)));
                }
            }
        } */
    //}
}
