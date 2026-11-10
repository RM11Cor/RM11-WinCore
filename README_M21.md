# FH5 Native Port — M21: real Vulkan shader rendering

A research test application, **not a playable Forza Horizon 5 port**.

M20 was verified on REDMAGIC 11 Pro, where the user reported 3/3 successful GPU texture uploads of original .swatchbin samples. M21 attempts to display the sampled textures using a Vulkan render pass, vertex and fragment shaders, sampled image descriptor, offscreen RGBA8 attachment and GPU-to-CPU readback.

Test procedure: install the GitHub Actions APK; tap **3 — Render real FH5 swatches**, select the same FH5_SWATCH_M12.zip file. Expected three previews if all formats and rendering work. Do not claim success on hardware before result.

No copyrighted game assets embedded in APK. Source files from user's own local ZIP via Android ACTION_OPEN_DOCUMENT.
