package gcdemangle;

import ghidra.app.util.demangler.DemangledException;
import ghidra.app.util.demangler.DemangledFunction;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.Demangler;
import ghidra.app.util.demangler.DemanglerOptions;
import ghidra.app.util.demangler.gnu.GnuDemanglerNativeProcess;
import ghidra.app.util.demangler.gnu.GnuDemanglerParser;
import ghidra.framework.Application;
import ghidra.program.model.listing.Program;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Library;
import java.io.FileNotFoundException;

public class SNDemangler implements Demangler {	
	static final int DEMANGLE_OPT_PARAMS =   1;
	static final int DEMANGLE_OPT_ANSI   =   2;
	static final int DEMANGLE_OPT_JAVA   =   4;
	static final int DEMANGLE_OPT_AUTO   =   8;
	static final int DEMANGLE_OPT_GNU    =  16;
	static final int DEMANGLE_OPT_LUCID  =  32;
	static final int DEMANGLE_OPT_ARM    =  64;
	static final int DEMANGLE_OPT_HP     = 128;
	static final int DEMANGLE_OPT_EDG    = 256;

	public interface SNDemanglerLib extends Library {
		Pointer mangle(String opname, int options);
		Pointer demangle(String mangled, int options);
		void free(Pointer str);
	}
	
	SNDemanglerLib _demanglerLib;
	SNDemanglerLib getDemanglerLib() throws DemangledException {
		if (_demanglerLib == null) {
			String libname = "sndemangle.so"; // todo dll
			try {
				_demanglerLib = Native.load(
					Application.getOSFile(libname).getAbsolutePath(),
					SNDemanglerLib.class);
			} catch (FileNotFoundException e) {
				throw new DemangledException("can't load " + libname);
			}		
		}
		
		return _demanglerLib;
	}
	
	@Override
	public boolean canDemangle(Program program) {
		return true;
	}

	@Override
	public DemangledObject demangle(String mangled, boolean demangleOnlyKnownPatterns) throws DemangledException {
		DemanglerOptions options = new DemanglerOptions();
		options.setApplySignature(true);
		options.setDoDisassembly(true);
		options.setDemangleOnlyKnownPatterns(demangleOnlyKnownPatterns);
		return this.demangle(mangled, options);
	}

	@Override
	public DemangledObject demangle(String mangled, DemanglerOptions options) throws DemangledException {
		SNDemanglerLib dmngl = getDemanglerLib();

		int opts = DEMANGLE_OPT_PARAMS
		        | DEMANGLE_OPT_ANSI
		        | DEMANGLE_OPT_AUTO
		        | DEMANGLE_OPT_GNU
		        | DEMANGLE_OPT_LUCID
		        | DEMANGLE_OPT_ARM
		        | DEMANGLE_OPT_HP
		        | DEMANGLE_OPT_EDG;
		Pointer demangled_ptr = dmngl.demangle(mangled, opts);
		String demangled = demangled_ptr.getString(0);
		dmngl.free(demangled_ptr);

		if (demangled.equals(mangled) || demangled.length() == 0)
			throw new DemangledException(true);
		
		DemangledObject demangledObject = parse(mangled, demangled, options.demangleOnlyKnownPatterns());

		return demangledObject;

//		if (demangledObject == null)
//			return demangledObject;

//		return null;
	}
	
	private DemangledObject parse(String mangled, String demangled, boolean demangleOnlyKnownPatterns) {
		if (demangleOnlyKnownPatterns && !isKnownMangledString(mangled, demangled)) {
			return null;
		}

		GnuDemanglerParser parser = new GnuDemanglerParser();
		DemangledObject demangledObject = parser.parse(mangled, demangled);
		return demangledObject;
	}
	
	private boolean isKnownMangledString(String mangled, String demangled) {
		return true; // lmfao
	}
}
