package com.rm11.autocore;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Small, platform-independent navigation state for Nova Explorer.
 * null means "This PC"; Back/Forward never manufacture new history entries.
 * Keeping history separate from rendering prevents repeated folder views.
 */
public final class NovaExplorerHistory {
    private static final int MAX_ENTRIES=64;
    private final List<File> back=new ArrayList<>();
    private final List<File> forward=new ArrayList<>();
    private File current;

    public File current(){return current;}
    public boolean canBack(){return !back.isEmpty();}
    public boolean canForward(){return !forward.isEmpty();}

    public void reset(File initial){
        back.clear();
        forward.clear();
        current=initial;
    }

    private static void push(List<File> stack,File value){
        if(stack.size()==MAX_ENTRIES)stack.remove(0);
        stack.add(value);
    }

    public boolean visit(File target){
        if(Objects.equals(current,target))return false;
        push(back,current);
        current=target;
        forward.clear();
        return true;
    }

    public boolean back(){
        if(!canBack())return false;
        push(forward,current);
        current=back.remove(back.size()-1);
        return true;
    }

    public boolean forward(){
        if(!canForward())return false;
        push(back,current);
        current=forward.remove(forward.size()-1);
        return true;
    }
}
