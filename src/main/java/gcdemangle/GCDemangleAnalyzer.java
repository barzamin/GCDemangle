/* Licensed under the Apache License, Version 2.0 (the "License");
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
package gcdemangle;

import ghidra.app.plugin.core.analysis.AbstractDemanglerAnalyzer;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.demangler.DemangledException;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerOptions;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Demangle gcc2 ProDG C++ symbols
 */
public class GCDemangleAnalyzer extends AbstractDemanglerAnalyzer {
    private SNDemangler demangler = new SNDemangler();
    
    public GCDemangleAnalyzer() {
        super("Demangle SN/ProDG", "Demangle gcc2 ProDG C++ symbols");
        setDefaultEnablement(true);
    }

    @Override
    public boolean canAnalyze(Program program) {
        return true;
    }

    @Override
    public void registerOptions(Options options, Program program) {
    }

    @Override
    protected DemangledObject doDemangle(String mangled, DemanglerOptions options, MessageLog log)
            throws DemangledException {
        return demangler.demangle(mangled, options);
    }
}
