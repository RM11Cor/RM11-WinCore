package com.rm11.autocore.engine;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Fail-closed integrity recheck of a previously staged engine data directory.
 *
 * A .verified-bundle marker is only a hint: the installed PE/DLLs might
 * have been modified after installation. Recompare every file against the
 * content-addressed signed-bundle ZIP and reject unexpected paths, symlinks
 * or missing entries. Never mutate, migrate or delete an existing install.
 *
 * Works on Java 17 (CI) and Android API 35. No Android runtime dependency.
 */
public final class EngineInstalledTreeVerifier {
    private static final int MAX_ENTRIES=10000;
    private EngineInstalledTreeVerifier(){}

    public static boolean matches(Path installedRoot,ZipFile trustedZip,
                                  String trustedBundleDigest) throws IOException {
        if(!Files.isDirectory(installedRoot,LinkOption.NOFOLLOW_LINKS)
                ||Files.isSymbolicLink(installedRoot))return false;
        Path marker=installedRoot.resolve(".verified-bundle");
        if(!Files.isRegularFile(marker,LinkOption.NOFOLLOW_LINKS)
                ||Files.size(marker)>100
                ||!Files.readString(marker).trim().equals(trustedBundleDigest))
            return false;
        Set<Path> expected=new HashSet<>();
        expected.add(marker);
        int count=0;
        java.util.Enumeration<? extends ZipEntry> entries=trustedZip.entries();
        while(entries.hasMoreElements()){
            ZipEntry item=entries.nextElement();
            if(++count>MAX_ENTRIES)return false;
            if(item.isDirectory())continue;
            String name=item.getName();
            if(!EngineDataStager.isAllowedDataEntry(name))return false;
            Path target=installedRoot.resolve(name).normalize();
            if(!target.startsWith(installedRoot)||!expected.add(target)
                    ||!Files.isRegularFile(target,LinkOption.NOFOLLOW_LINKS)
                    ||Files.isSymbolicLink(target)
                    ||Files.size(target)!=item.getSize())return false;
            try(InputStream actual=Files.newInputStream(target);
                InputStream original=trustedZip.getInputStream(item)){
                byte[] a=new byte[32768];
                byte[] b=new byte[32768];
                while(true){
                    int n=original.read(a);
                    if(n==-1){
                        if(actual.read()!=-1)return false;
                        break;
                    }
                    if(n==0)continue;
                    int offset=0;
                    while(offset<n){
                        int m=actual.read(b,offset,n-offset);
                        if(m<0)return false;
                        if(m==0)continue;
                        offset+=m;
                    }
                    for(int i=0;i<n;i++)if(a[i]!=b[i])return false;
                }
            }
        }
        // Reject all extras (including symlinked dirs, malicious injected
        // files and stale DLLs) instead of silently launching mixed engines.
        try(java.util.stream.Stream<Path> walk=Files.walk(installedRoot)){
            for(Path path:(Iterable<Path>)walk::iterator){
                if(Files.isSymbolicLink(path))return false;
                if(Files.isDirectory(path,LinkOption.NOFOLLOW_LINKS))continue;
                if(!Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)
                        ||!expected.remove(path))return false;
            }
        }
        return expected.isEmpty();
    }
}
