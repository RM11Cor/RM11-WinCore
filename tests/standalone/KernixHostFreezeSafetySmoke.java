package com.rm11.autocore.runtime;

public final class KernixHostFreezeSafetySmoke {
    private static void require(boolean ok){if(!ok)throw new AssertionError();}
    public static void main(String[] args){
        require(KernixHostFreezeSafetyV49151.blockUnqualifiedX11Diagnostics(true,false));
        require(KernixHostFreezeSafetyV49151.blockUnqualifiedX11Diagnostics(false,true));
        require(KernixHostFreezeSafetyV49151.blockUnqualifiedX11Diagnostics(true,true));
        require(!KernixHostFreezeSafetyV49151.blockUnqualifiedX11Diagnostics(false,false));
        System.out.println("KERNIX_HOST_FREEZE_X11_DIAGNOSTICS_QUARANTINED");
    }
}
