package com.fh5.port;

import android.content.ContentResolver;
import android.database.Cursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.DocumentsContract;
import android.provider.DocumentsContract.Document;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Set;
import java.util.HashSet;
import java.util.Locale;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.LinkedHashMap;

/**
 * Android SAF tree resolver. Some system file pickers filter ".exe" from
 * ACTION_OPEN_DOCUMENT. A folder tree grant instead lets the app query the
 * provider's actual child-document metadata and open the original PE64
 * document without renaming, copying, or unpacking any game files.
 *
 * Strict: only root or one directly nested game folder, only exact
 * ForzaHorizon5.exe, a PE64 AMD64 header check, bounded scanning, read only.
 * The returned URI is never included in the JSON diagnostic report.
 */
public final class SafGameFolderProbe {
    private SafGameFolderProbe() { }
    public static final int MAX_DIRECTORY_ROWS=25000;
    private static final int MAX_RECURSION_DEPTH=1;
    private static final long MAX_EXE_SIZE=1024L*1024*1024;

    public static final class Found {
        public final Uri documentUri;
        public final String parentDocumentId;
        public final long byteSize;
        public final int directoriesVisited, rowsScanned;
        private Found(Uri uri,String parentId,long size,int dirs,int rows) {
            documentUri=uri;parentDocumentId=parentId;byteSize=size;
            directoriesVisited=dirs;rowsScanned=rows;
        }
    }
    private static final class Budget {
        int rows, dirs;
    }
    public static Found find(ContentResolver resolver,Uri treeUri) throws IOException {
        if(treeUri==null || !"content".equals(treeUri.getScheme()) ||
            !DocumentsContract.isTreeUri(treeUri))
            throw new IOException("saf_tree_uri_required");
        final String rootId;
        try {rootId=DocumentsContract.getTreeDocumentId(treeUri);}
        catch(RuntimeException ex) {throw new IOException("saf_invalid_tree_document",ex);}
        if(rootId==null || rootId.isEmpty())throw new IOException("saf_empty_tree_document");
        Budget b=new Budget();
        Found result=scan(resolver,treeUri,rootId,0,b);
        if(result==null)throw new IOException("saf_forza_exe_not_visible_in_tree");
        return result;
    }
    private static Found scan(ContentResolver resolver,Uri treeUri,String parentId,
                              int depth,Budget budget) throws IOException {
        if(depth>MAX_RECURSION_DEPTH)return null;
        if(++budget.dirs>3)throw new IOException("saf_folder_depth_budget");
        final Uri children;
        try {children=DocumentsContract.buildChildDocumentsUriUsingTree(treeUri,parentId);}
        catch(RuntimeException ex) {throw new IOException("saf_child_query_not_supported",ex);}
        final String[] columns={Document.COLUMN_DOCUMENT_ID,
            Document.COLUMN_DISPLAY_NAME,Document.COLUMN_MIME_TYPE,Document.COLUMN_SIZE};
        String subFolder=null;
        try(Cursor c=resolver.query(children,columns,null,null,null)) {
            if(c==null)throw new IOException("saf_folder_query_unavailable");
            int ci=c.getColumnIndex(Document.COLUMN_DOCUMENT_ID);
            int ni=c.getColumnIndex(Document.COLUMN_DISPLAY_NAME);
            int mi=c.getColumnIndex(Document.COLUMN_MIME_TYPE);
            int si=c.getColumnIndex(Document.COLUMN_SIZE);
            if(ci<0||ni<0||mi<0)throw new IOException("saf_folder_columns_unavailable");
            while(c.moveToNext()) {
                if(++budget.rows>MAX_DIRECTORY_ROWS)
                    throw new IOException("saf_folder_listing_too_large");
                String id=c.getString(ci), name=c.getString(ni), mime=c.getString(mi);
                if(id==null||id.isEmpty()||name==null)continue;
                boolean directory=Document.MIME_TYPE_DIR.equals(mime);
                if(directory) {
                    if(depth==0 && "Forza Horizon 5".equalsIgnoreCase(name))
                        subFolder=id;
                    continue;
                }
                if(!"ForzaHorizon5.exe".equalsIgnoreCase(name))continue;
                long size=si>=0 && !c.isNull(si)?c.getLong(si):-1;
                if(size>MAX_EXE_SIZE || (size>=0 && size<256))
                    throw new IOException("saf_forza_exe_unexpected_size");
                final Uri exe;
                try {exe=DocumentsContract.buildDocumentUriUsingTree(treeUri,id);}
                catch(RuntimeException ex) {throw new IOException("saf_exe_document_invalid",ex);}
                // Validate actual MZ/PE32+/AMD64 before persisting the chosen
                // document, not just its filename or reported MIME.
                try(ParcelFileDescriptor pfd=resolver.openFileDescriptor(exe,"r")) {
                    if(pfd==null)throw new IOException("saf_exe_open_failed");
                    try(FileInputStream input=new FileInputStream(pfd.getFileDescriptor())) {
                        GameExeHeaderProbe.Result pe=
                            GameExeHeaderProbe.inspectDirectHeader(input.getChannel());
                        if(!pe.amd64 || !pe.pe32plus)
                            throw new IOException("saf_exe_not_amd64_pe32plus");
                        size=input.getChannel().size();
                    }
                }
                return new Found(exe,parentId,size,budget.dirs,budget.rows);
            }
        } catch(SecurityException ex) {
            throw new IOException("saf_tree_permission_denied",ex);
        } catch(IllegalArgumentException ex) {
            throw new IOException("saf_folder_query_unsupported",ex);
        }
        // A parent FH5_Extracted folder might contain the actual
        // Forza Horizon 5 directory. Traverse that ONE known named folder.
        if(subFolder!=null && depth==0)
            return scan(resolver,treeUri,subFolder,1,budget);
        return null;
    }

    /**
     * P3.5: Only list immediate DLL siblings of the exact verified EXE.
     * The file name itself is not sufficient to prove binary compatibility,
     * architecture, presence of exports, runtime installation or licensing.
     * No URIs, private paths or file bytes are exported.
     */
    public static Set<String> listSiblingDllNames(ContentResolver resolver,
                                                   Uri treeUri,Uri selectedExe)
            throws IOException {
        Found found=find(resolver,treeUri);
        if(selectedExe==null || !found.documentUri.equals(selectedExe))
            throw new IOException("saf_selected_exe_outside_selected_tree");
        Uri children=DocumentsContract.buildChildDocumentsUriUsingTree(
            treeUri,found.parentDocumentId);
        final String[] columns={Document.COLUMN_DISPLAY_NAME,Document.COLUMN_MIME_TYPE};
        Set<String> names=new HashSet<>();
        try(Cursor c=resolver.query(children,columns,null,null,null)) {
            if(c==null)throw new IOException("saf_sibling_query_unavailable");
            int n=c.getColumnIndex(Document.COLUMN_DISPLAY_NAME);
            int m=c.getColumnIndex(Document.COLUMN_MIME_TYPE);
            if(n<0||m<0)throw new IOException("saf_sibling_columns_unavailable");
            int rows=0;
            while(c.moveToNext()) {
                if(++rows>MAX_DIRECTORY_ROWS)
                    throw new IOException("saf_sibling_rows_over_budget");
                if(Document.MIME_TYPE_DIR.equals(c.getString(m)))continue;
                String name=c.getString(n);
                if(name!=null && name.matches("(?i)[a-z0-9_.-]{1,128}\\.dll"))
                    names.add(name.toLowerCase(Locale.ROOT));
            }
        } catch(SecurityException ex) {
            throw new IOException("saf_sibling_permission_denied",ex);
        } catch(IllegalArgumentException ex) {
            throw new IOException("saf_sibling_query_unsupported",ex);
        }
        return names;
    }


    public static final class LocalExportIndex {
        public final Map<String,PeExportIndex.Result> indexes;
        public final Map<String,String> dllStatuses;
        public final Set<String> localNames;
        private LocalExportIndex(Map<String,PeExportIndex.Result> results,
                 Map<String,String> statuses,Set<String> localNames) {
            indexes=java.util.Collections.unmodifiableMap(results);
            dllStatuses=java.util.Collections.unmodifiableMap(statuses);
            this.localNames=java.util.Collections.unmodifiableSet(localNames);
        }
    }

    /**
     * P3.8. Read-only PE export indexes for imported local DLL siblings.
     * Reading the export table does not imply the DLL is loadable/runnable.
     */
    public static LocalExportIndex inspectLocalDllExports(
            ContentResolver resolver,Uri treeUri,Uri selectedExe,
            Set<String> importedNames) throws IOException {
        Found found=find(resolver,treeUri);
        if(selectedExe==null||!found.documentUri.equals(selectedExe))
            throw new IOException("saf_export_exe_not_inside_selected_tree");
        Uri children=DocumentsContract.buildChildDocumentsUriUsingTree(
            treeUri,found.parentDocumentId);
        String[] cols={Document.COLUMN_DOCUMENT_ID,
            Document.COLUMN_DISPLAY_NAME,Document.COLUMN_MIME_TYPE};
        Map<String,String> fileIds=new LinkedHashMap<>();
        Set<String> localNames=new HashSet<>();
        try(Cursor c=resolver.query(children,cols,null,null,null)){
            if(c==null)throw new IOException("saf_export_children_query_unavailable");
            int id=c.getColumnIndex(Document.COLUMN_DOCUMENT_ID);
            int name=c.getColumnIndex(Document.COLUMN_DISPLAY_NAME);
            int mime=c.getColumnIndex(Document.COLUMN_MIME_TYPE);
            if(id<0||name<0||mime<0)
                throw new IOException("saf_export_query_columns_missing");
            int rows=0;
            while(c.moveToNext()){
                if(++rows>MAX_DIRECTORY_ROWS)
                    throw new IOException("saf_export_directory_budget");
                if(Document.MIME_TYPE_DIR.equals(c.getString(mime)))continue;
                String n=c.getString(name),documentId=c.getString(id);
                if(n==null||documentId==null)continue;
                String lower=n.toLowerCase(Locale.ROOT);
                if(!lower.matches("[a-z0-9_.-]{1,128}\\.dll") ||
                  importedNames==null||!importedNames.contains(lower))continue;
                localNames.add(lower);
                if(!fileIds.containsKey(lower)&&fileIds.size()<MAX_LOCAL_DLL_HEADER_CHECKS)
                    fileIds.put(lower,documentId);
            }
        } catch(SecurityException ex){
            throw new IOException("saf_export_permission_denied",ex);
        } catch(IllegalArgumentException ex){
            throw new IOException("saf_export_query_unsupported",ex);
        }
        Map<String,PeExportIndex.Result> indexes=new LinkedHashMap<>();
        Map<String,String> statuses=new LinkedHashMap<>();
        for(Map.Entry<String,String> item:fileIds.entrySet()){
            String state="EXPORT_INDEX_READ_FAILED";
            try {
                Uri dll=DocumentsContract.buildDocumentUriUsingTree(
                    treeUri,item.getValue());
                try(ParcelFileDescriptor pfd=resolver.openFileDescriptor(dll,"r")){
                    if(pfd==null)throw new IOException("saf_export_dll_open_failed");
                    try(FileInputStream in=new FileInputStream(pfd.getFileDescriptor())){
                        PeExportIndex.Result exports=PeExportIndex.inspect(in.getChannel());
                        indexes.put(item.getKey(),exports);
                        state=exports.status;
                    }
                }
            } catch(IOException|SecurityException|IllegalArgumentException ex){
                String err=ex.getMessage();
                if(err!=null && err.matches("pe_exports_[a-z0-9_]{2,90}"))
                    state=err;
            }
            statuses.put(item.getKey(),state);
        }
        return new LocalExportIndex(indexes,statuses,localNames);
    }

    public static final int MAX_LOCAL_DLL_HEADER_CHECKS=16;
    public static final class LocalDll {
        public final String dll,headerStatus;
        public final long fileSize;
        private LocalDll(String name,String status,long bytes) {
            dll=name;headerStatus=status;fileSize=bytes;
        }
    }

    /**
     * Only the explicitly user-granted extracted game directory is queried.
     * At most 16 exact imported DLL sibling headers are opened read-only.
     * No DLL is loaded, mapped or executed. No private URI is exported.
     */
    public static List<LocalDll> inspectSiblingDllHeaders(
        ContentResolver resolver,Uri treeUri,Uri selectedExe,Set<String> imported)
            throws IOException {
        Found found=find(resolver,treeUri);
        if(selectedExe==null||!found.documentUri.equals(selectedExe))
            throw new IOException("saf_exe_not_part_of_selected_folder");
        Uri children=DocumentsContract.buildChildDocumentsUriUsingTree(
            treeUri,found.parentDocumentId);
        String[] cols={Document.COLUMN_DOCUMENT_ID,
            Document.COLUMN_DISPLAY_NAME,Document.COLUMN_MIME_TYPE};
        Map<String,String> targets=new LinkedHashMap<>();
        try(Cursor c=resolver.query(children,cols,null,null,null)) {
            if(c==null)throw new IOException("saf_dll_query_unavailable");
            int id=c.getColumnIndex(Document.COLUMN_DOCUMENT_ID);
            int name=c.getColumnIndex(Document.COLUMN_DISPLAY_NAME);
            int mime=c.getColumnIndex(Document.COLUMN_MIME_TYPE);
            if(id<0||name<0||mime<0)throw new IOException("saf_dll_columns_missing");
            int count=0;
            while(c.moveToNext()) {
                if(++count>MAX_DIRECTORY_ROWS)
                    throw new IOException("saf_dll_listing_budget_reached");
                if(Document.MIME_TYPE_DIR.equals(c.getString(mime)))continue;
                String filename=c.getString(name),documentId=c.getString(id);
                if(filename==null||documentId==null)continue;
                String normalized=filename.toLowerCase(Locale.ROOT);
                if(!normalized.matches("[a-z0-9_.-]{1,128}\\.dll") ||
                   imported==null || !imported.contains(normalized))continue;
                if(!targets.containsKey(normalized) && targets.size()<MAX_LOCAL_DLL_HEADER_CHECKS)
                    targets.put(normalized,documentId);
            }
        } catch(SecurityException ex) {
            throw new IOException("saf_dll_permission_denied",ex);
        } catch(IllegalArgumentException ex) {
            throw new IOException("saf_dll_query_unsupported",ex);
        }
        List<LocalDll> output=new ArrayList<>();
        for(Map.Entry<String,String> item:targets.entrySet()) {
            String status="DLL_HEADER_OPEN_FAILED";
            long bytes=-1;
            try {
                Uri dll=DocumentsContract.buildDocumentUriUsingTree(treeUri,item.getValue());
                try(ParcelFileDescriptor pfd=resolver.openFileDescriptor(dll,"r")) {
                    if(pfd==null)throw new IOException("saf_dll_open_unavailable");
                    try(FileInputStream input=new FileInputStream(pfd.getFileDescriptor())) {
                        PeDllHeaderValidator.Result checked=
                            PeDllHeaderValidator.inspect(input.getChannel());
                        status=checked.status;bytes=checked.fileBytes;
                    }
                }
            } catch(IOException|SecurityException|IllegalArgumentException ex) {
                status="DLL_HEADER_READ_UNAVAILABLE";
            }
            output.add(new LocalDll(item.getKey(),status,bytes));
        }
        return output;
    }

    /** P3.9: target of a forwarded export, not executable code. */
    public static final class LocalForwarders {
        public final Map<String,PeForwarderProbe.Result> reports;
        public final Map<String,String> fileStatuses;
        public final Set<String> immediateDllNames;
        LocalForwarders(Map<String,PeForwarderProbe.Result> reports,
                        Map<String,String> statuses,Set<String> siblings) {
            this.reports=java.util.Collections.unmodifiableMap(reports);
            this.fileStatuses=java.util.Collections.unmodifiableMap(statuses);
            this.immediateDllNames=java.util.Collections.unmodifiableSet(siblings);
        }
    }
    /**
     * Inspect only local DLLs with imports independently classified as
     * FORWARDED_EXPORT by PeLocalImportLinkProbe. Open read-only via
     * user-granted SAF tree; do NOT follow target DLL references.
     */
    public static LocalForwarders inspectForwarderTargets(
             ContentResolver resolver,Uri treeUri,Uri selectedExe,
             Map<String,List<String>> forwardedNames) throws IOException {
        if(forwardedNames==null||forwardedNames.size()>MAX_LOCAL_DLL_HEADER_CHECKS)
            throw new IOException("saf_forwarder_dll_count_budget");
        Found found=find(resolver,treeUri);
        if(selectedExe==null||!selectedExe.equals(found.documentUri))
            throw new IOException("saf_forwarder_exe_not_in_selected_tree");
        Uri children=DocumentsContract.buildChildDocumentsUriUsingTree(
            treeUri,found.parentDocumentId);
        String[] cols={Document.COLUMN_DOCUMENT_ID,
            Document.COLUMN_DISPLAY_NAME,Document.COLUMN_MIME_TYPE};
        Map<String,String> selected=new LinkedHashMap<>();
        Set<String> siblings=new HashSet<>();
        try(Cursor c=resolver.query(children,cols,null,null,null)) {
            if(c==null)throw new IOException("saf_forwarder_query_unavailable");
            int i=c.getColumnIndex(Document.COLUMN_DOCUMENT_ID);
            int n=c.getColumnIndex(Document.COLUMN_DISPLAY_NAME);
            int t=c.getColumnIndex(Document.COLUMN_MIME_TYPE);
            if(i<0||n<0||t<0)throw new IOException("saf_forwarder_query_columns_missing");
            int rows=0;
            while(c.moveToNext()) {
                if(++rows>MAX_DIRECTORY_ROWS)
                    throw new IOException("saf_forwarder_directory_budget");
                if(Document.MIME_TYPE_DIR.equals(c.getString(t)))continue;
                String name=c.getString(n),id=c.getString(i);
                if(id==null||name==null)continue;
                String lower=name.toLowerCase(Locale.ROOT);
                if(!lower.matches("[a-z0-9_.-]{1,128}\\.dll"))continue;
                siblings.add(lower);
                if(forwardedNames.containsKey(lower)&&!selected.containsKey(lower))
                    selected.put(lower,id);
            }
        } catch(SecurityException ex) {
            throw new IOException("saf_forwarder_permission_denied",ex);
        } catch(IllegalArgumentException ex) {
            throw new IOException("saf_forwarder_query_unsupported",ex);
        }
        Map<String,PeForwarderProbe.Result> reports=new LinkedHashMap<>();
        Map<String,String> status=new LinkedHashMap<>();
        for(Map.Entry<String,List<String>> entry:forwardedNames.entrySet()) {
            String dll=entry.getKey(),id=selected.get(dll);
            if(id==null) {
                status.put(dll,"FORWARDED_DLL_NOT_FOUND_BESIDE_EXE");
                continue;
            }
            try {
                Uri file=DocumentsContract.buildDocumentUriUsingTree(treeUri,id);
                try(ParcelFileDescriptor pfd=resolver.openFileDescriptor(file,"r")) {
                    if(pfd==null)throw new IOException("saf_forwarder_dll_open_failed");
                    try(FileInputStream in=new FileInputStream(pfd.getFileDescriptor())) {
                        PeExportIndex.Result exports=PeExportIndex.inspect(in.getChannel());
                        PeForwarderProbe.Result forwarders=PeForwarderProbe.inspect(
                            in.getChannel(),exports,new java.util.LinkedHashSet<>(
                                entry.getValue()));
                        reports.put(dll,forwarders);
                        status.put(dll,forwarders.status);
                    }
                }
            } catch(IOException|SecurityException|IllegalArgumentException ex) {
                String cause=ex.getMessage();
                if(cause==null||!cause.matches("(pe|saf)_[a-z0-9_]{2,90}"))
                    cause="LOCAL_FORWARDER_READ_UNAVAILABLE";
                status.put(dll,cause);
            }
        }
        return new LocalForwarders(reports,status,siblings);
    }
}
