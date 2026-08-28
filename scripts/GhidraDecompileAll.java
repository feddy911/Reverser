// Ghidra headless: full dump (functions + decompile + imports + thunks + strings + callees + dlls).
// Usage: -postScript GhidraDecompileAll.java <output.json>
// @category Reverser
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.symbol.SourceType;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class GhidraDecompileAll extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            throw new Exception("Usage: GhidraDecompileAll <output.json>");
        }
        String outPath = args[0];

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        List<String> funcEntries = new ArrayList<>();
        List<String> importEntries = new ArrayList<>();
        List<String> thunkEntries = new ArrayList<>();
        int total = 0;
        int ok = 0;

        FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
        while (funcs.hasNext() && !monitor.isCancelled()) {
            Function func = funcs.next();
            total++;
            String name = func.getName();
            long funcAddr = func.getEntryPoint().getOffset();

            if (func.isExternal()) {
                importEntries.add(escapeJson(name));
                continue;
            }

            if (func.isThunk()) {
                Function target = func.getThunkedFunction(true);
                String t = "null";
                if (target != null && !target.isExternal()) {
                    t = "\"0x" + Long.toHexString(target.getEntryPoint().getOffset()) + "\"";
                }
                thunkEntries.add("  {\"address\": \"0x" + Long.toHexString(funcAddr) + "\", " +
                        "\"name\": " + escapeJson(name) + ", " +
                        "\"target\": " + t + "}");
                continue;
            }

            boolean libMatched = false;
            try {
                String cmt = func.getComment();
                libMatched = (cmt != null && cmt.contains("Library Function"));
                if (!libMatched) {
                    libMatched = (func.getSymbol().getSource() == SourceType.ANALYSIS);
                }
            } catch (Exception e) {
                // ignore
            }

            long size;
            try {
                size = func.getBody().getNumAddresses();
            } catch (Exception e) {
                size = 0;
            }

            List<String> calleeAddrs = new ArrayList<>();
            List<String> calleeExts = new ArrayList<>();
            List<String> calleeDlls = new ArrayList<>();
            try {
                Set<Function> called = func.getCalledFunctions(monitor);
                for (Function c : called) {
                    if (c.isExternal()) {
                        calleeExts.add(escapeJson(c.getName()));
                        String dll = "";
                        try {
                            if (c.getParentNamespace() != null) {
                                dll = c.getParentNamespace().getName();
                            }
                        } catch (Exception e) {
                            // ignore
                        }
                        calleeDlls.add(escapeJson(dll));
                    } else {
                        calleeAddrs.add("\"0x" + Long.toHexString(c.getEntryPoint().getOffset()) + "\"");
                    }
                }
            } catch (Exception e) {
                // ignore
            }

            String code = "";
            try {
                DecompileResults res = decomp.decompileFunction(func, 30, monitor);
                if (res != null && res.decompileCompleted()) {
                    DecompiledFunction df = res.getDecompiledFunction();
                    if (df != null && df.getC() != null) {
                        code = df.getC();
                        ok++;
                    }
                }
            } catch (Exception e) {
                code = "";
            }

            funcEntries.add(
                "  {\"address\": \"0x" + Long.toHexString(funcAddr) + "\", " +
                "\"name\": " + escapeJson(name) + ", " +
                "\"size\": " + size + ", " +
                "\"callees\": [" + String.join(",", calleeAddrs) + "], " +
                "\"ext_calls\": [" + String.join(",", calleeExts) + "], " +
                "\"ext_dlls\": [" + String.join(",", calleeDlls) + "], " +
                "\"lib_matched\": " + (libMatched ? "true" : "false") + ", " +
                "\"ghidra_code\": " + escapeJson(code) + "}"
            );
        }

        List<String> stringEntries = new ArrayList<>();
        for (Data d : currentProgram.getListing().getDefinedData(true)) {
            if (monitor.isCancelled()) break;
            Object v = d.getValue();
            if (v instanceof String) {
                String s = (String) v;
                if (s.length() >= 4 && s.length() <= 200) {
                    long a = d.getAddress().getOffset();
                    stringEntries.add(
                        "  {\"address\": \"0x" + Long.toHexString(a) + "\", " +
                        "\"string\": " + escapeJson(s) + "}"
                    );
                }
            }
        }

        decomp.dispose();

        try (PrintWriter pw = new PrintWriter(
                new OutputStreamWriter(new FileOutputStream(outPath), StandardCharsets.UTF_8))) {
            pw.println("{");
            pw.println("\"functions\": [");
            pw.println(String.join(",\n", funcEntries));
            pw.println("],");
            pw.println("\"imports\": [");
            pw.println(String.join(",\n", importEntries));
            pw.println("],");
            pw.println("\"thunks\": [");
            pw.println(String.join(",\n", thunkEntries));
            pw.println("],");
            pw.println("\"strings\": [");
            pw.println(String.join(",\n", stringEntries));
            pw.println("]");
            pw.println("}");
        }

        println("GHIDRA_DUMP_OK: funcs=" + total + " decompiled=" + ok +
                " imports=" + importEntries.size() +
                " thunks=" + thunkEntries.size() +
                " strings=" + stringEntries.size());
    }

    private String escapeJson(String s) {
        if (s == null) return "null";
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\': sb.append("\\\\"); break;
                case '"':  sb.append("\\\""); break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append("\"");
        return sb.toString();
    }
}