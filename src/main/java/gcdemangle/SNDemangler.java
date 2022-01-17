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
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class SNDemangler implements Demangler { 
    static final Map<String, String> specialOpTable = initSpecialOpTable();
    
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

    private boolean shouldDemangle(String symbol) {
    	// must have a dunderscore in it
    	if (!symbol.contains("__"))
    		return false;

    	// but can't start w it
    	if (symbol.indexOf("__", 1) < 0)
    		return false;

    	return true;
    }

    @Override
    public DemangledObject demangle(String mangled, DemanglerOptions options) throws DemangledException {
        if (!shouldDemangle(mangled))
        	return null;

        return null;
    }

    private static Map<String, String> initSpecialOpTable() {
        var map = new HashMap<String, String>();
        map.put("nw", "operator new"); // DEMANGLE_OPT_ANSI, new (1.92,  ansi)
        map.put("dl", "operator delete"); // DEMANGLE_OPT_ANSI, new (1.92,   ansi)
        map.put("new", "operator new"); // 0, old (1.91,     and 1.x)
        map.put("delete", "operator delete"); // 0, old (1.91,   and 1.x)
        map.put("vn", "operator new []"); // DEMANGLE_OPT_ANSI, GNU, pending ansi
        map.put("vd", "operator delete []"); // DEMANGLE_OPT_ANSI, GNU, pending ansi
        map.put("as", "operator ="); // DEMANGLE_OPT_ANSI, ansi
        map.put("ne", "operator !="); // DEMANGLE_OPT_ANSI, old, ansi
        map.put("eq", "operator =="); // DEMANGLE_OPT_ANSI, old,    ansi
        map.put("ge", "operator >="); // DEMANGLE_OPT_ANSI, old,    ansi
        map.put("gt", "operator >"); // DEMANGLE_OPT_ANSI, old, ansi
        map.put("le", "operator <="); // DEMANGLE_OPT_ANSI, old,    ansi
        map.put("lt", "operator <"); // DEMANGLE_OPT_ANSI, old, ansi
        map.put("plus", "operator +"); // 0, old
        map.put("pl", "operator +"); // DEMANGLE_OPT_ANSI, ansi
        map.put("apl", "operator +="); // DEMANGLE_OPT_ANSI, ansi
        map.put("minus", "operator -"); // 0, old
        map.put("mi", "operator -"); // DEMANGLE_OPT_ANSI, ansi
        map.put("ami", "operator -="); // DEMANGLE_OPT_ANSI, ansi
        map.put("mult", "operator *"); // 0, old
        map.put("ml", "operator *"); // DEMANGLE_OPT_ANSI, ansi
        map.put("amu", "operator *="); // DEMANGLE_OPT_ANSI, ansi (ARM/Lucid)
        map.put("aml", "operator *="); // DEMANGLE_OPT_ANSI, ansi (GNU/g++)
        map.put("convert", "operator +"); // 0, old (unary +)
        map.put("negate", "operator -"); // 0, old (unary -)
        map.put("trunc_mod", "operator %"); // 0, old
        map.put("md", "operator %"); // DEMANGLE_OPT_ANSI, ansi
        map.put("amd", "operator %="); // DEMANGLE_OPT_ANSI, ansi
        map.put("trunc_div", "operator /"); // 0, old
        map.put("dv", "operator /"); // DEMANGLE_OPT_ANSI, ansi
        map.put("adv", "operator /="); // DEMANGLE_OPT_ANSI, ansi
        map.put("truth_andif", "operator &&"); // 0, old
        map.put("aa", "operator &&"); // DEMANGLE_OPT_ANSI, ansi
        map.put("truth_orif", "operator ||"); // 0, old
        map.put("oo", "operator ||"); // DEMANGLE_OPT_ANSI, ansi
        map.put("truth_not", "operator !"); // 0, old
        map.put("nt", "operator !"); // DEMANGLE_OPT_ANSI, ansi
        map.put("postincrement", "operator ++"); // 0, old
        map.put("pp", "operator ++"); // DEMANGLE_OPT_ANSI, ansi
        map.put("postdecrement", "operator --"); // 0, old
        map.put("mm", "operator --"); // DEMANGLE_OPT_ANSI, ansi
        map.put("bit_ior", "operator |"); // 0, old
        map.put("or", "operator |"); // DEMANGLE_OPT_ANSI, ansi
        map.put("aor", "operator |="); // DEMANGLE_OPT_ANSI, ansi
        map.put("bit_xor", "operator ^"); // 0, old
        map.put("er", "operator ^"); // DEMANGLE_OPT_ANSI, ansi
        map.put("aer", "operator ^="); // DEMANGLE_OPT_ANSI, ansi
        map.put("bit_and", "operator &"); // 0, old
        map.put("ad", "operator &"); // DEMANGLE_OPT_ANSI, ansi
        map.put("aad", "operator &="); // DEMANGLE_OPT_ANSI, ansi
        map.put("bit_not", "operator ~"); // 0, old
        map.put("co", "operator ~"); // DEMANGLE_OPT_ANSI, ansi
        map.put("call", "operator ()"); // 0, old
        map.put("cl", "operator ()"); // DEMANGLE_OPT_ANSI, ansi
        map.put("alshift", "operator <<"); // 0, old
        map.put("ls", "operator <<"); // DEMANGLE_OPT_ANSI, ansi
        map.put("als", "operator <<="); // DEMANGLE_OPT_ANSI, ansi
        map.put("arshift", "operator >>"); // 0, old
        map.put("rs", "operator >>"); // DEMANGLE_OPT_ANSI, ansi
        map.put("ars", "operator >>="); // DEMANGLE_OPT_ANSI, ansi
        map.put("component", "operator ->"); // 0, old
        map.put("pt", "operator ->"); // DEMANGLE_OPT_ANSI, ansi; Lucid C++ form
        map.put("rf", "operator ->"); // DEMANGLE_OPT_ANSI, ansi; ARM/GNU form
        map.put("indirect", "operator *"); // 0, old
        map.put("method_call", "operator ->()"); // 0, old
        map.put("addr", "operator &"); // 0, old (unary &)
        map.put("array", "operator []"); // 0, old
        map.put("vc", "operator []"); // DEMANGLE_OPT_ANSI, ansi
        map.put("compound", "operator ,"); // 0, old
        map.put("cm", "operator ,"); // DEMANGLE_OPT_ANSI, ansi
        map.put("cond", "operator ?:"); // 0, old
        map.put("cn", "operator ?:"); // DEMANGLE_OPT_ANSI, pseudo-ansi
        map.put("max", "operator >?"); // 0, old
        map.put("mx", "operator >?"); // DEMANGLE_OPT_ANSI, pseudo-ansi
        map.put("min", "operator <?"); // 0, old
        map.put("mn", "operator <?"); // DEMANGLE_OPT_ANSI, pseudo-ansi
        map.put("rm", "operator ->*"); // DEMANGLE_OPT_ANSI, ansi
        map.put("sz", "operator sizeof"); // DEMANGLE_OPT_ANSI, pseudo-ansi

        return Collections.unmodifiableMap(map);
    }
}
