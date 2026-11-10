# FH5 M22 Vulkan 3D mesh preview
Personal research app: not FH5 game or ForzaTech runtime.

User's geometry package FH5_M22_Geometry_Staging.zip contains FHMS v1 with 22,945 vertices, 53,259 indices, 17 groups. The native parser validates header, counts, offsets and all indices before Vulkan allocation.

M22 implementation intends a real indexed triangle draw with per-group diagnostic colors, MVP-like shader projection, depth buffer and offscreen Vulkan GPU readback to Android ImageView. Camera rotation controlled by buttons.

No game assets are embedded in the distributed APK or public source repository. Import the geometry ZIP using Android's file picker. Native M22 hardware test is only proven after testing on actual Android device; GitHub Actions builds are compile verification only.
