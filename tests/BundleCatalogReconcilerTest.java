import com.rm11cor.carxstreet.portlab.BundleCatalogReconciler;

public final class BundleCatalogReconcilerTest {
    private static int count=0;
    private static void ok(boolean condition,String reason) {
        if(!condition)throw new AssertionError(reason);
        count++;
    }
    private static String p(String name) {
        return "{UnityEngine.AddressableAssets.Addressables.RuntimePath}/aa/StandaloneWindows64/"+name;
    }
    public static void main(String[] args) {
        var a=new BundleCatalogReconciler();
        a.addPhysicalWindowsBundle("one.bundle");
        a.addPhysicalWindowsBundle("two.bundle");
        a.addPhysicalWindowsBundle("unlisted.bundle");
        a.addCatalogInternalId(p("one.bundle"));
        a.addCatalogInternalId(p("two.bundle"));
        var r=a.summarize(true,true);
        ok(r.fullReconciliationValid,"complete SAF + catalog proof");
        ok(r.physicalEntries==3 && r.catalogWindowsReferences==2,"two separate source counts");
        ok(r.unreferencedPhysicalCount==1 &&
                r.unreferencedPhysicalExamples.contains("unlisted.bundle"),
                "physical orphan classified without pretending file lost");
        ok(r.notPresentOnDiskCount==0,"no catalog-only entry despite off-by-one");
        ok(r.filenameMatches==2,"matched physical sources");

        var b=new BundleCatalogReconciler();
        b.addPhysicalWindowsBundle("one.bundle");
        b.addCatalogInternalId(p("one.bundle"));
        b.addCatalogInternalId(p("one.bundle"));
        b.addCatalogInternalId(p("missing.bundle"));
        var t=b.summarize(true,true);
        ok(t.catalogWindowsReferences==3&&t.distinctCatalogReferencedFilenames==2,
                "duplicate catalog id not counted as two different bundles");
        ok(t.catalogDuplicateReferenceEntries==1,"duplicate count visible");
        ok(t.notPresentOnDiskCount==1 &&
                t.notPresentOnDiskExamples.contains("missing.bundle"),
                "catalog references missing physical basename");
        ok(t.unreferencedPhysicalCount==0,"no physical orphan when all actual tracked");

        var c=new BundleCatalogReconciler();
        c.addPhysicalWindowsBundle("MiXeD.BUNDLE");
        c.addCatalogInternalId(p("mixed.bundle"));
        ok(c.summarize(true,true).filenameMatches==1,
                "case insensitive Android SAF / Windows source names");

        var d=new BundleCatalogReconciler();
        d.addPhysicalWindowsBundle("one.bundle");
        d.addCatalogInternalId(p("one.bundle"));
        ok(!d.summarize(false,true).fullReconciliationValid,
                "partial physical scan not a complete audit");
        ok(!d.summarize(true,false).fullReconciliationValid,
                "partial catalog parse not a complete audit");

        var e=new BundleCatalogReconciler();
        e.addCatalogInternalId(p("subdirectory/a.bundle"));
        var z=e.summarize(true,true);
        ok(!z.fullReconciliationValid && z.invalidOrNonlocalWindowsReferences==1,
                "unparseable nested Windows64 path blocks full audit");

        var f=new BundleCatalogReconciler();
        f.addCatalogInternalId("local:///aa/StandaloneWindows64/item.bundle?token=SECRET");
        f.addPhysicalWindowsBundle("item.bundle");
        ok(f.summarize(true,true).filenameMatches==1,
                "query stripped before Windows bundle filename match");

        var g=new BundleCatalogReconciler();
        g.addCatalogInternalId("x/aa/StandaloneWindows64/a.bundle");
        g.addCatalogInternalId("x/aa/StandaloneWindows64/a.bundle");
        g.addPhysicalWindowsBundle("A.bundle");
        g.addPhysicalWindowsBundle("a.bundle");
        var k=g.summarize(true,true);
        ok(k.physicalDuplicateCasefoldNames==1&&k.distinctPhysicalFilenames==1,
                "duplicate physical names must not masquerade as unique files");

        var h=new BundleCatalogReconciler();
        h.addCatalogInternalId("https://example.com/private/a.bundle?auth=SECRET&android=1");
        h.addCatalogInternalId("aa/StandaloneAndroid/cars.bundle");
        var m=h.summarize(true,true);
        ok(m.androidNamedCount==2&&m.androidPlatformPathCount==1,
                "Android word differs from Android build-targeted resource");
        ok(!m.androidNameExamples.toString().contains("SECRET"),
                "no URL query token exposed in report");
        ok(m.androidNameExamples.contains("cars.bundle"),
                "plain Android-target path basename can be reported");
        ok(m.distinctCatalogReferencedFilenames==0,
                "non Windows paths do not count toward Windows bundle references");

        var i=new BundleCatalogReconciler();
        i.addCatalogInternalId(p("../../secret.bundle"));
        ok(!i.summarize(true,true).fullReconciliationValid,
                "ambiguous traversal path must not be matched");
        var j=new BundleCatalogReconciler();
        j.addPhysicalWindowsBundle("good.bundle");
        j.addCatalogInternalId(p("bad name.bundle"));
        ok(!j.summarize(true,true).fullReconciliationValid,
                "unsafe invalid source bundle name rejected");
        var q=new BundleCatalogReconciler();
        q.addCatalogInternalId("generic/base/android_support.dat");
        ok(q.summarize(true,true).androidPlatformPathCount==0,
                "generic Android word is not target-platform evidence");

        System.out.println("CARX_BUNDLE_CATALOG_RECONCILIATION_"+count+"_NEGATIVE_CONTROLS_PASS");
    }
}
