package com.rm11cor.carxstreet.portlab;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Exact per-file-name census of the original Windows64 Addressables catalog
 * against real files listed by Android SAF. Pure Java; no read/write of
 * proprietary bundles, no execution and no asset conversion.
 *
 * Counts of references != counts of distinct bundle files. A difference
 * of one alone CANNOT be called a missing game asset.
 */
public final class BundleCatalogReconciler {
    private static final int MAX_BUNDLES=12_000;
    private static final int MAX_EXAMPLES=12;
    private final Map<String,Integer> actual=new HashMap<>();
    private final Map<String,Integer> referenced=new HashMap<>();
    private final ArrayList<String> androidNamedExamples=new ArrayList<>();
    private int actualEntries=0;
    private int windowsReferences=0;
    private int invalidWindowsReferences=0;
    private int androidNamedReferences=0;
    private int androidTargetPathReferences=0;
    private boolean limitHit=false;

    /** Feed each original physical file name from StandaloneWindows64. */
    public void addPhysicalWindowsBundle(String basename) {
        actualEntries++;
        String normalized=normalizedBundleBasename(basename);
        if(normalized==null||actual.size()>=MAX_BUNDLES && !actual.containsKey(normalized)) {
            limitHit=true;
            return;
        }
        actual.put(normalized,actual.getOrDefault(normalized,0)+1);
    }

    /** Feed each m_InternalIds JSON value exactly once, without opening assets. */
    public void addCatalogInternalId(String original) {
        if(original==null||original.length()>8192) {
            limitHit=true;
            return;
        }
        String safe=original.replace('\\','/');
        String lower=safe.toLowerCase(Locale.ROOT);
        int query=safe.indexOf('?');
        int fragment=safe.indexOf('#');
        int cut=safe.length();
        if(query>=0)cut=Math.min(cut,query);
        if(fragment>=0)cut=Math.min(cut,fragment);
        String noQuery=safe.substring(0,cut);
        String path=noQuery.toLowerCase(Locale.ROOT);
        if(lower.contains("android")) {
            androidNamedReferences++;
            if(path.contains("/standaloneandroid/") ||
                    path.contains("/aa/android/") || path.contains("/android/"))
                androidTargetPathReferences++;
            if(androidNamedExamples.size()<MAX_EXAMPLES) {
                // No URLs, query strings, access tokens or absolute paths.
                String simple=sanitizedNonSecretSuffix(noQuery);
                androidNamedExamples.add(simple);
            }
        }
        int segment=path.indexOf("standalonewindows64/");
        if(segment<0)return;
        windowsReferences++;
        String after=noQuery.substring(segment+"standalonewindows64/".length());
        // Do not infer nested path or URL mappings or create false matches.
        if(after.indexOf('/')>=0) {
            invalidWindowsReferences++;
            return;
        }
        String normalized=normalizedBundleBasename(after);
        if(normalized==null) {
            invalidWindowsReferences++;
            return;
        }
        if(referenced.size()>=MAX_BUNDLES&&!referenced.containsKey(normalized)){
            limitHit=true;
            return;
        }
        referenced.put(normalized,referenced.getOrDefault(normalized,0)+1);
    }

    private static String normalizedBundleBasename(String name) {
        if(name==null||name.isEmpty()||name.length()>180)return null;
        String lowered=name.toLowerCase(Locale.ROOT);
        if(!lowered.endsWith(".bundle"))return null;
        // Windows bundle names are ASCII identifiers. Reject path, escape,
        // control chars and special tokens rather than constructing a match.
        if(!lowered.matches("[a-z0-9][a-z0-9._-]{0,179}\\.bundle"))return null;
        return lowered;
    }

    private static String sanitizedNonSecretSuffix(String path) {
        int start=path.lastIndexOf('/');
        String item=path.substring(start+1);
        if(item.length()>100||!item.matches("[A-Za-z0-9._-]+"))
            return "[redacted_nonlocal_or_ambiguous_id]";
        return item;
    }

    public static final class Summary {
        public int physicalEntries;
        public int distinctPhysicalFilenames;
        public int physicalDuplicateCasefoldNames;
        public int catalogWindowsReferences;
        public int distinctCatalogReferencedFilenames;
        public int catalogDuplicateReferenceEntries;
        public int invalidOrNonlocalWindowsReferences;
        public int filenameMatches;
        public int unreferencedPhysicalCount;
        public int notPresentOnDiskCount;
        public int androidNamedCount;
        public int androidPlatformPathCount;
        public boolean fullReconciliationValid;
        public ArrayList<String> unreferencedPhysicalExamples=new ArrayList<>();
        public ArrayList<String> notPresentOnDiskExamples=new ArrayList<>();
        public ArrayList<String> androidNameExamples=new ArrayList<>();
        public String status;
    }

    public Summary summarize(boolean sourceFileListingComplete,
                             boolean catalogFullyParsed) {
        Summary r=new Summary();
        r.physicalEntries=actualEntries;
        r.distinctPhysicalFilenames=actual.size();
        r.catalogWindowsReferences=windowsReferences;
        r.distinctCatalogReferencedFilenames=referenced.size();
        r.invalidOrNonlocalWindowsReferences=invalidWindowsReferences;
        r.androidNamedCount=androidNamedReferences;
        r.androidPlatformPathCount=androidTargetPathReferences;
        r.androidNameExamples.addAll(androidNamedExamples);
        for(int count:actual.values())r.physicalDuplicateCasefoldNames+=count-1;
        for(int count:referenced.values())r.catalogDuplicateReferenceEntries+=count-1;
        for(String key:actual.keySet()) {
            if(referenced.containsKey(key))r.filenameMatches++;
            else {
                r.unreferencedPhysicalCount++;
                r.unreferencedPhysicalExamples.add(key);
            }
        }
        for(String key:referenced.keySet()) {
            if(!actual.containsKey(key)){
                r.notPresentOnDiskCount++;
                r.notPresentOnDiskExamples.add(key);
            }
        }
        Collections.sort(r.unreferencedPhysicalExamples);
        Collections.sort(r.notPresentOnDiskExamples);
        truncate(r.unreferencedPhysicalExamples);
        truncate(r.notPresentOnDiskExamples);
        r.fullReconciliationValid=sourceFileListingComplete && catalogFullyParsed &&
                !limitHit && invalidWindowsReferences==0;
        r.status=!sourceFileListingComplete?"physical_SAF_scan_incomplete":
                !catalogFullyParsed?"Addressables_catalog_not_fully_parsed":
                limitHit?"bundle_count_or_input_limit_exceeded":
                invalidWindowsReferences>0?"ambiguous_windows_bundle_path_cannot_exact_match":
                "complete_filename_level_comparison_not_bundle_content_integrity";
        return r;
    }
    private static void truncate(ArrayList<String> examples) {
        if(examples.size()>MAX_EXAMPLES)
            examples.subList(MAX_EXAMPLES,examples.size()).clear();
    }
}
