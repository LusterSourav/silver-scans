import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.address.AddressSet;
import ghidra.util.task.TaskMonitor;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

public class ExtractInfo extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String outputFile = getScriptArgs()[0];
        PrintWriter out = new PrintWriter(new FileWriter(outputFile));
        
        out.println("=== Functions ===");
        Function func = getFirstFunction();
        while (func != null) {
            out.println("FUNC: " + func.getName() + " @ " + func.getEntryPoint() + " size=" + func.getBody().getNumAddresses());
            func = getFunctionAfter(func);
        }
        
        out.println("\n=== Strings ===");
        var stringIter = currentProgram.getListing().getDefinedData(true);
        while (stringIter.hasNext()) {
            var data = stringIter.next();
            if (data.getDataType().getName().equals("string")) {
                out.println("STR: " + data.getAddress() + " = " + data.getValue());
            }
        }
        
        out.println("\n=== Imports ===");
        var extFuncs = currentProgram.getFunctionManager().getExternalFunctions();
        while (extFuncs.hasNext()) {
            var ef = extFuncs.next();
            out.println("IMPORT: " + ef.getName() + " @ " + ef.getEntryPoint());
        }
        
        out.println("\n=== Sections ===");
        var blocks = currentProgram.getMemory().getBlocks();
        for (var block : blocks) {
            out.println("SECTION: " + block.getName() + " " + block.getStart() + "-" + block.getEnd() + " RWX=" + block.isRead() + block.isWrite() + block.isExecute());
        }
        
        out.close();
        println("Analysis complete. Output: " + outputFile);
    }
}