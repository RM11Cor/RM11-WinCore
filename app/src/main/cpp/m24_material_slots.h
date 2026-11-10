#pragma once
// M24 verified on user's VW Beetle traffic body modelbin + M8 OBJ usemtl + M22 FHMS.
// Material slots are original model references; colors and light response are DIAGNOSTIC.
#include <cstdint>
#include <cstring>
namespace fh5m24 {
constexpr uint32_t groupSlots[17]={4,3,1,1,1,1,1,5,7,10,11,12,6,8,9,0,2};
constexpr const char* materialNames[13]={
    "ClearGlass","DarkGlass","Decals","DetailOpacity","Light_Emmisive",
    "MSE_Left","MSE_Platelight","MSE_Right","MultiSwatch",
    "MultiSwatchEmissive","TrafficCarpaint_Main",
    "TrafficCarpaint_Secondary","White_Plastic"
};
constexpr const char* referencedMaterialbin[13]={
    "Clear_Glass","dark_glass","detail_diffalphamaskgloss",
    "detail_diffAlphaGlossNorm","MultiSwatch_Emissive",
    "MultiSwatch_Emissive","MultiSwatch_Emissive","MultiSwatch_Emissive",
    "MultiSwatch","MultiSwatch_Emissive","trafficCarpaint","trafficCarpaint","colour_glass"
};
constexpr const char* groupNames[17]={
    "part_1_bone_root","part_2_bone_root","part_3_bone_root",
    "part_4_bone_boneWiperBladeL","part_5_bone_boneWiperBladeR",
    "part_6_bone_boneWiperL","part_7_bone_boneWiperR",
    "part_8_bone_root","part_9_bone_root","part_10_bone_root",
    "part_11_bone_root","part_12_bone_root","part_13_bone_root",
    "part_14_bone_root","part_15_bone_root","part_16_bone_root",
    "part_17_bone_root"
};
// RGB normalized values and a light-response boost; NONE are pulled from real FH5 shader parameters.
struct DebugMaterial { float rgb[3]; float emissive; };
constexpr DebugMaterial palette[13]={
    {{0.48f,0.79f,0.92f},0.02f}, // 0 Clear glass - diagnostic cyan
    {{0.12f,0.23f,0.33f},0.00f}, // 1 Dark glass
    {{0.94f,0.63f,0.28f},0.00f}, // 2 Decals
    {{0.63f,0.67f,0.71f},0.00f}, // 3 Detail opacity
    {{1.00f,0.82f,0.40f},0.52f}, // 4 Light emissive
    {{0.95f,0.26f,0.23f},0.37f}, // 5 Left light
    {{0.93f,0.87f,0.57f},0.36f}, // 6 Plate light
    {{0.95f,0.26f,0.23f},0.37f}, // 7 Right light
    {{0.75f,0.73f,0.70f},0.00f}, // 8 MultiSwatch
    {{0.87f,0.60f,0.38f},0.24f}, // 9 MultiSwatch emissive
    {{0.24f,0.62f,0.87f},0.00f}, // 10 main paint
    {{0.90f,0.88f,0.80f},0.00f}, // 11 secondary paint
    {{0.80f,0.81f,0.76f},0.00f}  // 12 white plastic
};
static_assert(sizeof(groupSlots)/sizeof(groupSlots[0])==17,"M24 part count");
static_assert(sizeof(palette)/sizeof(palette[0])==13,"M24 material count");
}
