package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;

public final class WineGraphicsBackendEvidenceTest {
    @Test public void offModeDetectsNoUsableVulkanOrOpenGlWithoutNamingFex() {
        WineGraphicsBackendEvidence e=new WineGraphicsBackendEvidence();
        e.accept("00ac:err:vulkan:vulkan_init_once Failed to load libvulkan.so.1\n");
        e.accept("00ac:err:wgl:X11DRV_OpenGLInit Failed to load libGL: dlopen failed: ");
        e.accept("library \"libGL.so.1\" not found\n");
        e.accept("00ac:err:wgl:X11DRV_OpenGLInit OpenGL support is disabled.\n");
        e.accept("00ac:err:d3d:wined3d_caps_gl_ctx_create Failed to find a suitable pixel format.\n");
        e.accept("00ac:err:d3d:wined3d_adapter_gl_init Failed to get a GL context for adapter 00ff.\n");
        String s=e.snapshot();
        assertTrue(s.contains("RM11_V471_LINUX_VULKAN_SONAME_LOAD_FAILED=true"));
        assertTrue(s.contains("RM11_V471_LIBGL_SO1_LOAD_FAILED=true"));
        assertTrue(s.contains("RM11_V471_WINED3D_GL_CONTEXT_FAILED=true"));
        assertTrue(s.contains("RM11_V471_BACKEND_STATUS=VULKAN_AND_DESKTOP_OPENGL_UNAVAILABLE_IN_WINE_OUTPUT"));
        assertTrue(s.contains("RM11_V471_WSI_PRESENTATION=UNVERIFIED"));
        assertFalse(s.contains("FEX_FAULT_CONFIRMED"));
    }

    @Test public void androidLoaderDlopenDoesNotProveRendering() {
        WineGraphicsBackendEvidence e=new WineGraphicsBackendEvidence();
        e.accept("RM11_V458_VULKAN_LINUX_SONAME_MISSING_ATTEMPT_ANDROID_LOADER\n");
        e.accept("RM11_V458_ANDROID_VULKAN_DLOPEN_SUCCESS\n");
        String s=e.snapshot();
        assertTrue(s.contains("RM11_V471_ANDROID_VULKAN_DLOPEN_SUCCESS=true"));
        assertTrue(s.contains("RM11_V471_BACKEND_STATUS=ANDROID_VULKAN_LOADER_REACHED_WSI_UNVERIFIED"));
        assertTrue(s.contains("RM11_V471_DXVK_GAME_RENDERING=UNVERIFIED"));
    }

    @Test public void longPartialInputRemainsBounded() {
        WineGraphicsBackendEvidence e=new WineGraphicsBackendEvidence();
        for(int i=0;i<300;i++)e.accept("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        e.accept("\n");
        assertTrue(e.snapshot().length()<1800);
    }
}
