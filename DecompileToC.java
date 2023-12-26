/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//Decompile an entire program to C

/* This code from: https://github.com/h4sh5/ghidra-headless-decompile */

import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Arrays;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.Option;
import ghidra.app.util.exporter.CppExporter;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;

public class DecompileToC extends GhidraScript {
	@Override
	public void run() throws Exception {
		// if (!state.displayParameterGatherer("Script Options")) {
		// 	return;
		// }

		String[] args = getScriptArgs();

		System.out.println("ARGS: " + Arrays.toString(args));

		// File outputFile = (File) state.getEnvironmentVar("COutputFile");
		File outputFile = new File(args[0]);

		CppExporter cppExporter = new CppExporter();
		List<Option> options = new ArrayList<Option>();
		options.add(new Option(CppExporter.CREATE_HEADER_FILE, Boolean.TRUE));
		cppExporter.setOptions(options);
		cppExporter.setExporterServiceProvider(state.getTool());
		cppExporter.export(outputFile, currentProgram, null, monitor);

        SymbolTable mySymbolTable = currentProgram.getSymbolTable();
        String header_path = outputFile.getPath().replace(".c", ".h");
        FileWriter fw = new FileWriter(header_path, true);
        fw.write(";\n\n", 0, 2);
        fw.write("typedef unsigned int uint;\n", 0, 27);
        for(Symbol sym : mySymbolTable.getSymbolIterator()) {
            if(sym.isGlobal() && !sym.isExternal() && sym.getReferenceCount() > 0 &&
                    sym.getSymbolType() == SymbolType.LABEL) {
                if(DataUtilities.getDataAtAddress(currentProgram, sym.getAddress()) != null) {
                    DataType dt = DataUtilities.getDataAtAddress(currentProgram, sym.getAddress()).getBaseDataType();
                    //System.err.println(dt.getDisplayName());
                    //System.err.println(sym.getName());
                    int sub_pos = dt.getDisplayName().indexOf('[');
                    if(sub_pos < 0) {
                        fw.write(dt.getDisplayName(), 0, dt.getDisplayName().length());
                        fw.write(" ", 0, 1);
                        fw.write(sym.getName(), 0, sym.getName().length());
                        fw.write(";\n", 0, 2);
                    } else {
                        fw.write(dt.getDisplayName(), 0, sub_pos);
                        fw.write(" ", 0, 1);
                        fw.write(sym.getName(), 0, sym.getName().length());
                        fw.write(dt.getDisplayName(), sub_pos, dt.getDisplayName().length() - sub_pos);
                        fw.write(";\n", 0, 2);
                    }
                }
            }
        }
        fw.close();
	}
}
