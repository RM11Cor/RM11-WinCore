package com.rm11.autocore.runtime;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

/**
 * Controlled investigation of RM11 user-device v482: X11 connected, 12 root
 * children, zero viewable windows, Wine game and server still alive.
 *
 * A passive X11 core QueryTree/GetWindowAttributes/GetGeometry inventory is
 * ALWAYS recorded. If and only if there is EXACTLY ONE unmapped, full-screen
 * InputOutput top-level window, issue one XMapWindow and verify the result.
 *
 * No global WM changes, user data access, window titles, kill or resize.
 * The game runner invokes it only after 24s with repeated empty X11 samples.
 */
public final class X11HiddenWindowRecoveryV483 {
    private static final int MAX_REPLY=262144;
    private X11HiddenWindowRecoveryV483(){}
    private static int u16(byte[] b,int i){
        return (b[i]&255)|((b[i+1]&255)<<8);
    }
    private static long u32(byte[] b,int i){
        return (b[i]&255L)|((b[i+1]&255L)<<8)
               |((b[i+2]&255L)<<16)|((b[i+3]&255L)<<24);
    }
    private static void put32(byte[] b,int i,long value){
        for(int j=0;j<4;j++)b[i+j]=(byte)(value>>>(j*8));
    }
    private static byte[] reply(DataInputStream in)throws IOException{
        byte[] header=new byte[32];
        in.readFully(header);
        if((header[0]&255)!=1)throw new IOException("X11_UNEXPECTED_REPLY_"+(header[0]&255));
        long extra=u32(header,4)*4L;
        if(extra<0||extra>MAX_REPLY)throw new IOException("X11_REPLY_OVERSIZED");
        byte[] result=new byte[32+(int)extra];
        System.arraycopy(header,0,result,0,32);
        in.readFully(result,32,(int)extra);
        return result;
    }
    private static byte[] request(OutputStream out,DataInputStream in,
            int opcode,long resource)throws IOException {
        byte[] cmd=new byte[8];
        cmd[0]=(byte)opcode;
        cmd[2]=2;
        put32(cmd,4,resource);
        out.write(cmd);
        out.flush();
        return reply(in);
    }

    public static String inspectWithoutMapping(){
        return inspect(false);
    }
    public static String inspectAndRecoverOnce(){
        return inspect(true);
    }

    private static String inspect(boolean allowMap) {
        StringBuilder evidence=new StringBuilder("RM11_V483_X11_UNMAPPED_WINDOW_INVENTORY\n");
        evidence.append("RM11_V484_MAPPING_ALLOWED=").append(allowMap).append('\n');
        try(Socket socket=new Socket()){
            socket.connect(new InetSocketAddress(InetAddress.getByName("127.0.0.1"),
                    NativeX11TcpBridge.TCP_PORT),1800);
            socket.setSoTimeout(1800);
            DataInputStream input=new DataInputStream(socket.getInputStream());
            OutputStream output=socket.getOutputStream();
            output.write(new byte[]{'l',0,11,0,0,0,0,0,0,0,0,0});
            output.flush();
            byte[] start=new byte[8];
            input.readFully(start);
            if((start[0]&255)!=1)return evidence+"RM11_V483_X11_SETUP_FAILED\n";
            int configSize=u16(start,6)*4;
            if(configSize<40||configSize>MAX_REPLY)
                return evidence+"RM11_V483_X11_SETUP_OVERSIZED\n";
            byte[] setup=new byte[configSize];
            input.readFully(setup);
            int formats=setup[21]&255,vendor=u16(setup,16);
            int screenOffset=32+((vendor+3)&~3)+formats*8;
            if((setup[20]&255)<1||screenOffset+40>setup.length)
                return evidence+"RM11_V483_X11_ROOT_NOT_FOUND\n";
            long root=u32(setup,screenOffset);
            int rootW=u16(setup,screenOffset+20),rootH=u16(setup,screenOffset+22);
            evidence.append("RM11_V483_ROOT_GEOMETRY=").append(rootW).append('x')
                    .append(rootH).append('\n');
            byte[] tree=request(output,input,15,root);
            int count=u16(tree,16);
            if(32L+count*4L>tree.length)
                return evidence+"RM11_V483_TREE_TRUNCATED\n";
            evidence.append("RM11_V483_ROOT_CHILDREN=").append(count).append('\n');
            int limit=Math.min(count,48);
            List<Long> candidates=new ArrayList<>();
            int mapped=0,ordinaryUnmapped=0;
            for(int i=0;i<limit;i++) {
                long child=u32(tree,32+i*4);
                if(child==root)continue; // absolute protection
                try {
                    byte[] attr=request(output,input,3,child);
                    byte[] geom=request(output,input,14,child);
                    int state=attr[26]&255;
                    int clazz=u16(attr,12);
                    boolean override=attr[27]!=0;
                    int w=u16(geom,16),h=u16(geom,18);
                    if(state==2)mapped++;
                    if(state==0&&clazz==1)ordinaryUnmapped++;
                    evidence.append("RM11_V483_WINDOW_").append(i)
                        .append("=id:").append(Long.toHexString(child))
                        .append(" class:").append(clazz)
                        .append(" state:").append(state)
                        .append(" override:").append(override)
                        .append(" geometry:").append(w).append('x').append(h)
                        .append('\n');
                    if(X11HiddenWindowRecoveryPolicyV483.isCandidate(
                           clazz,state,override,w,h,rootW,rootH))
                        candidates.add(child);
                }catch(IOException unstableWindow) {
                    evidence.append("RM11_V483_WINDOW_").append(i)
                            .append("=CHANGED_DURING_SCAN\n");
                }
            }
            evidence.append("RM11_V483_WINDOWS_VIEWABLE=").append(mapped).append('\n')
                    .append("RM11_V483_WINDOWS_INPUTOUTPUT_UNMAPPED=")
                    .append(ordinaryUnmapped).append('\n')
                    .append("RM11_V483_FULLSCREEN_UNMAPPED_CANDIDATES=")
                    .append(candidates.size()).append('\n');
            if(!allowMap){
                evidence.append("RM11_V484_RECOVERY=PASSIVE_SCAN_NO_MAPPING\n");
            }else if(mapped>0){
                evidence.append("RM11_V483_RECOVERY=SKIPPED_OTHER_WINDOWS_VISIBLE\n");
            }else if(candidates.size()!=1){
                evidence.append("RM11_V483_RECOVERY=SKIPPED_NO_UNIQUE_SAFE_TARGET\n");
            }else {
                long selected=candidates.get(0);
                byte[] map=new byte[8];
                map[0]=8; // X11 core MapWindow, no reply
                map[2]=2; // request length 2 * 4 bytes
                put32(map,4,selected);
                output.write(map);
                output.flush();
                evidence.append("RM11_V483_RECOVERY=XMAPWINDOW_ONE_SHOT\n");
                evidence.append("RM11_V483_SELECTED_WINDOW_ID=")
                        .append(Long.toHexString(selected)).append('\n');
                byte[] after=request(output,input,3,selected);
                int afterState=after[26]&255;
                evidence.append("RM11_V483_POST_MAP_STATE=").append(afterState).append('\n')
                        .append("RM11_V483_POST_MAP_VIEWABLE=").append(afterState==2).append('\n');
            }
        }catch(Exception error){
            evidence.append("RM11_V483_RECOVERY_ERROR=")
                    .append(error.getClass().getSimpleName()).append('\n');
        }
        evidence.append("RM11_V483_RENDERING_AND_GAME_WINDOW_OWNERSHIP=UNVERIFIED\n");
        return evidence.toString();
    }
}
