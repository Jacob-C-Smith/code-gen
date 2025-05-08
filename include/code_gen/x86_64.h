/** !
 * x86_64 code generator 
 * 
 * @file code_gen/x86_64.h 
 * 
 * @author Jacob Smith 
 */

// Include guard
#pragma once

// Standard library
#include <stdio.h>
#include <time.h>

// POSIX
#include <sys/mman.h>

// log module
#include <log/log.h>

// sync module
#include <sync/sync.h>

// pack module
#include <pack/pack.h>

// code gen
#include <code_gen/code_gen.h>

// Platform dependent macros
//

// Platform dependent typedefs
//

// Enumeration definitions

// Enumerations
enum x86_64_op_e 
{
    X86_64_REG_8,
    X86_64_REG_16,
    X86_64_REG_32,
    X86_64_REG_64,
    X86_64_REG_128,
    X86_64_REG_256,
    X86_64_REG_512,
    X86_64_IMM64,
};

enum x86_64_reg_e
{
    RAX = 0b000,
    RCX = 0b001,
    RDX = 0b010,
    RBX = 0b011,
    RSP = 0b100,
    RBP = 0b101,
    RSI = 0b110,    
    RDI = 0b111,
    R8  = 0b1000,
    R9  = 0b1001,
    R10 = 0b1010,
    R11 = 0b1011,
    R12 = 0b1100,
    R13 = 0b1101,
    R14 = 0b1110,
    R15 = 0b1111,
    XMM0  = 0b000,
    XMM1  = 0b001,
    XMM2  = 0b010,
    XMM3  = 0b011,
    XMM4  = 0b100,
    XMM5  = 0b101,
    XMM6  = 0b110,
    XMM7  = 0b111,
    XMM8  = 0b1000,
    XMM9  = 0b1001,
    XMM10 = 0b1010,
    XMM11 = 0b1011,
    XMM12 = 0b1100,
    XMM13 = 0b1101,
    XMM14 = 0b1110,
    XMM15 = 0b1111,
    YMM0  = 0b000,
    YMM1  = 0b001,
    YMM2  = 0b010,
    YMM3  = 0b011,
    YMM4  = 0b100,
    YMM5  = 0b101,
    YMM6  = 0b110,
    YMM7  = 0b111,
    YMM8  = 0b1000,
    YMM9  = 0b1001,
    YMM10 = 0b1010,
    YMM11 = 0b1011,
    YMM12 = 0b1100,
    YMM13 = 0b1101,
    YMM14 = 0b1110,
    YMM15 = 0b1111,
    ZMM0  = 0b000,
    ZMM1  = 0b001,
    ZMM2  = 0b010,
    ZMM3  = 0b011,
    ZMM4  = 0b100,
    ZMM5  = 0b101,
    ZMM6  = 0b110,
    ZMM7  = 0b111,
    ZMM8  = 0b1000,
    ZMM9  = 0b1001,
    ZMM10 = 0b1010,
    ZMM11 = 0b1011,
    ZMM12 = 0b1100,
    ZMM13 = 0b1101,
    ZMM14 = 0b1110,
    ZMM15 = 0b1111
};

// Structure definitions
struct x86_64_code_gen_s
{
    size_t         size;
    void          *p_base;
    unsigned char *p_offset;
};

struct x86_64_op_s
{
    enum x86_64_op_e _type;

    union
    {
        enum x86_64_reg_e  _reg;
        unsigned long long _imm64;
    };
};


// Type definitions
typedef struct x86_64_op_s       x86_64_op;
typedef struct x86_64_code_gen_s x86_64_code_gen;

// Constructors
int x86_64_code_gen_construct ( x86_64_code_gen **pp_x86_64_code_gen, void *p_out, size_t size );
int x86_64_code_gen_node_construct ( x86_64_code_gen *p_code_gen, char *instruction, char *op1, char *op2, char *op3 );

// Stack
size_t x86_64_gen_push_reg ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg );
size_t x86_64_gen_pop_reg  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg );

// Bitwise
size_t x86_64_gen_and_r64_r64  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_or_r64_r64   ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_xor_r64_r64  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_test_r64_r64 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_not_reg      ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg ); 
size_t x86_64_gen_shl_reg_imm8 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, unsigned char imm8 );
size_t x86_64_gen_shr_reg_imm8 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, unsigned char imm8 );
size_t x86_64_gen_rol_reg_imm8 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, unsigned char imm8 );
size_t x86_64_gen_ror_reg_imm8 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, unsigned char imm8 );

// Arithmetic
size_t x86_64_gen_add_r64_r64 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_sub_r64_r64 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_neg_reg     ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg );
size_t x86_64_gen_mul_reg     ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg );
size_t x86_64_gen_imul_reg    ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg );
size_t x86_64_gen_div_reg     ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg );
size_t x86_64_gen_idiv_reg    ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg );
size_t x86_64_gen_inc_reg     ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg );
size_t x86_64_gen_dec_reg     ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg );

// Flow control
size_t x86_64_gen_jmp_reg  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg );
size_t x86_64_gen_call_reg ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg );
size_t x86_64_gen_ret      ( x86_64_code_gen *p_code_gen );

// Move
size_t x86_64_gen_mov_reg_imm64 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, long long imm64 );
size_t x86_64_gen_mov_r64_r64   ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );

// Misc
size_t x86_64_gen_nop     ( x86_64_code_gen *p_code_gen );
size_t x86_64_gen_syscall ( x86_64_code_gen *p_code_gen );

// AVX
size_t x86_64_avx_gen_add_reg128_reg128 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );

// Comparison operations
size_t x86_64_gen_cmp_r64_r64    ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_cmp_r64_imm32  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, int imm32 );
size_t x86_64_gen_je_rel32       ( x86_64_code_gen *p_code_gen, int rel32 );
size_t x86_64_gen_jne_rel32      ( x86_64_code_gen *p_code_gen, int rel32 );
size_t x86_64_gen_jg_rel32       ( x86_64_code_gen *p_code_gen, int rel32 );
size_t x86_64_gen_jge_rel32      ( x86_64_code_gen *p_code_gen, int rel32 );
size_t x86_64_gen_jl_rel32       ( x86_64_code_gen *p_code_gen, int rel32 );
size_t x86_64_gen_jle_rel32      ( x86_64_code_gen *p_code_gen, int rel32 );

// Memory operations
size_t x86_64_gen_mov_reg_mem    ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, enum x86_64_reg_e _base, int32_t disp );
size_t x86_64_gen_mov_mem_reg    ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _base, int32_t disp, enum x86_64_reg_e _reg );
size_t x86_64_gen_lea_r64_mem    ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, enum x86_64_reg_e _base, enum x86_64_reg_e _index, uint8_t scale, int32_t disp );

// SIMD/Vector operations (AVX/AVX2/AVX-512)
size_t x86_64_gen_vmovdqu_ymm_ymm   ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vpaddd_ymm_ymm_ymm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vpsubq_ymm_ymm_ymm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vpmulld_ymm_ymm_ymm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vdivps_ymm_ymm_ymm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );

// AVX-512 specific operations
size_t x86_64_gen_vmovdqu64_zmm_zmm   ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vpaddq_zmm_zmm_zmm  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vpmulld_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vdivpd_zmm_zmm_zmm  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );

// Bit manipulation instructions
size_t x86_64_gen_bswap_r64  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg );
size_t x86_64_gen_popcnt_r64 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_tzcnt_r64  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_lzcnt_r64  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );

// System operations
size_t x86_64_gen_rdtsc      ( x86_64_code_gen *p_code_gen );
size_t x86_64_gen_cpuid      ( x86_64_code_gen *p_code_gen );
size_t x86_64_gen_mfence     ( x86_64_code_gen *p_code_gen );
size_t x86_64_gen_lfence     ( x86_64_code_gen *p_code_gen );
size_t x86_64_gen_sfence     ( x86_64_code_gen *p_code_gen );

// AVX-512 Data Movement Instructions
size_t x86_64_gen_vmovaps_zmm_zmm    ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vmovapd_zmm_zmm    ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vbroadcastf32x4_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vbroadcastf64x4_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vbroadcasti32x4_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vbroadcasti64x4_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );

// AVX-512 Arithmetic Instructions
size_t x86_64_gen_vaddps_zmm_zmm_zmm  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vaddpd_zmm_zmm_zmm  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vsubps_zmm_zmm_zmm  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vsubpd_zmm_zmm_zmm  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vmulps_zmm_zmm_zmm  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vmulpd_zmm_zmm_zmm  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vfmadd132ps_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vfmadd213ps_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vfmadd231ps_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vrsqrt14ps_zmm_zmm  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vrcp14ps_zmm_zmm    ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );

// AVX-512 Integer Instructions
size_t x86_64_gen_vpaddd_zmm_zmm_zmm  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vpaddq_zmm_zmm_zmm  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vpsubd_zmm_zmm_zmm  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vpsubq_zmm_zmm_zmm  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vpmulld_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vpmullq_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );

// AVX-512 Comparison Instructions
size_t x86_64_gen_vcmpps_zmm_zmm_zmm_imm8 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3, uint8_t imm8 );
size_t x86_64_gen_vcmppd_zmm_zmm_zmm_imm8 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3, uint8_t imm8 );
size_t x86_64_gen_vpcmpd_k_zmm_zmm_imm8   ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3, uint8_t imm8 );
size_t x86_64_gen_vpcmpq_k_zmm_zmm_imm8   ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3, uint8_t imm8 );

// AVX-512 Mask Operations
size_t x86_64_gen_kmovw          ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_kandw          ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_kandn          ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_kunpckbw       ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );

// AVX-512 Permute/Shuffle Operations
size_t x86_64_gen_vpermps_zmm_zmm_zmm    ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vpermpd_zmm_zmm_zmm    ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vpermd_zmm_zmm_zmm     ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vpermq_zmm_zmm_zmm     ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vshufps_zmm_zmm_zmm_imm8 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3, uint8_t imm8 );
size_t x86_64_gen_vshufpd_zmm_zmm_zmm_imm8 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3, uint8_t imm8 );

// AVX-512 Type Conversion Instructions
size_t x86_64_gen_vcvtps2pd_zmm_ymm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vcvtpd2ps_ymm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vcvtps2dq_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vcvtdq2ps_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vcvttpd2dq_ymm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vcvttps2dq_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );

// AVX-512 Advanced Vector Math Operations
size_t x86_64_gen_vsqrtps_zmm_zmm      ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vsqrtpd_zmm_zmm      ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vexp2ps_zmm_zmm      ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vexp2pd_zmm_zmm      ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vlog2ps_zmm_zmm      ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vlog2pd_zmm_zmm      ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vrangeps_zmm_zmm_zmm_imm8 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3, uint8_t imm8 );
size_t x86_64_gen_vrangepd_zmm_zmm_zmm_imm8 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3, uint8_t imm8 );

// AVX-512 Trigonometric Functions
size_t x86_64_gen_vsinps_zmm_zmm       ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vcosps_zmm_zmm       ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vtanps_zmm_zmm       ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vrcpps_zmm_zmm       ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );

// AVX-512 Advanced Bit Manipulation
size_t x86_64_gen_vpternlogd_zmm_zmm_zmm_imm8 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3, uint8_t imm8 );
size_t x86_64_gen_vpternlogq_zmm_zmm_zmm_imm8 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3, uint8_t imm8 );
size_t x86_64_gen_vpsllvd_zmm_zmm_zmm  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vpsrlvd_zmm_zmm_zmm  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vpsravd_zmm_zmm_zmm  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vprorq_zmm_zmm_imm8  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, uint8_t imm8 );
size_t x86_64_gen_vprolq_zmm_zmm_imm8  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, uint8_t imm8 );

// AVX-512 Scatter/Gather Operations
size_t x86_64_gen_vgatherdps_zmm_mem   ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _base, enum x86_64_reg_e _index, uint8_t scale );
size_t x86_64_gen_vgatherdpd_zmm_mem   ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _base, enum x86_64_reg_e _index, uint8_t scale );
size_t x86_64_gen_vscatterdps_mem_zmm  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _base, enum x86_64_reg_e _index, uint8_t scale, enum x86_64_reg_e _reg1 );
size_t x86_64_gen_vscatterdpd_mem_zmm  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _base, enum x86_64_reg_e _index, uint8_t scale, enum x86_64_reg_e _reg1 );

// AVX-512 Reduction Operations
size_t x86_64_gen_vreduceps_zmm_zmm_imm8 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, uint8_t imm8 );
size_t x86_64_gen_vreducepd_zmm_zmm_imm8 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, uint8_t imm8 );
size_t x86_64_gen_vfpclassps_k_zmm_imm8  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, uint8_t imm8 );
size_t x86_64_gen_vfpclasspd_k_zmm_imm8  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, uint8_t imm8 );

// AVX-512 Miscellaneous SIMD Operations
size_t x86_64_gen_vfixupimmps_zmm_zmm_zmm_imm8 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3, uint8_t imm8 );
size_t x86_64_gen_vfixupimmpd_zmm_zmm_zmm_imm8 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3, uint8_t imm8 );
size_t x86_64_gen_vgetexpps_zmm_zmm   ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vgetexppd_zmm_zmm   ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vgetmantps_zmm_zmm_imm8 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, uint8_t imm8 );
size_t x86_64_gen_vgetmantpd_zmm_zmm_imm8 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, uint8_t imm8 );

// AVX-512 Conflict Detection Instructions
size_t x86_64_gen_vpconflictd_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vpconflictq_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vplzcntd_zmm_zmm    ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vplzcntq_zmm_zmm    ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );

// AVX-512 Compression Instructions
size_t x86_64_gen_vpcompressq_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vpcompressd_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vpexpandq_zmm_zmm   ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vpexpandd_zmm_zmm   ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );

// AVX-512F Foundation Instructions - Data Movement
size_t x86_64_gen_vmovups_zmm_zmm    ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vmovupd_zmm_zmm    ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vmovdqu8_zmm_zmm   ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vmovdqu16_zmm_zmm  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vmovdqu32_zmm_zmm  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vmovdqu64_zmm_zmm  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );

// AVX-512F - Arithmetic Operations
size_t x86_64_gen_vaddps_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vaddpd_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vsubps_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vsubpd_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vmulps_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vmulpd_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vdivps_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vdivpd_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );

// AVX-512F - FMA Operations
size_t x86_64_gen_vfmadd132ps_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vfmadd213ps_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vfmadd231ps_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vfmsub132ps_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vfmsub213ps_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vfmsub231ps_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );

// AVX-512F - Compare Operations
size_t x86_64_gen_vcmpps_k_zmm_zmm_imm8 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, uint8_t imm8 );
size_t x86_64_gen_vcmppd_k_zmm_zmm_imm8 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, uint8_t imm8 );

// AVX-512BW - Byte and Word Operations
size_t x86_64_gen_vpaddb_zmm_zmm_zmm    ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vpaddw_zmm_zmm_zmm    ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vpsubb_zmm_zmm_zmm    ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vpsubw_zmm_zmm_zmm    ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vpmullw_zmm_zmm_zmm   ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vpmulhw_zmm_zmm_zmm   ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );

// AVX-512DQ - Double and Quad-word Operations
size_t x86_64_gen_vandpd_zmm_zmm_zmm    ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vandnpd_zmm_zmm_zmm   ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vorpd_zmm_zmm_zmm     ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vxorpd_zmm_zmm_zmm    ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );

// AVX-512IFMA - Integer Fused Multiply-Add
size_t x86_64_gen_vpmadd52luq_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vpmadd52huq_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );

// AVX-512VBMI - Vector Byte Manipulation
size_t x86_64_gen_vpermi2b_zmm_zmm_zmm  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vpermt2b_zmm_zmm_zmm  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vpmultishiftqb_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );

// AVX-512VBMI2 - Vector Byte Manipulation 2
size_t x86_64_gen_vpcompressb_zmm_zmm  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vpcompressw_zmm_zmm  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vpexpandb_zmm_zmm    ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vpexpandw_zmm_zmm    ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );

// AVX-512VNNI - Vector Neural Network Instructions
size_t x86_64_gen_vpdpbusd_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vpdpbusds_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vpdpwssd_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vpdpwssds_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );

// AVX-512BITALG - Bit Algorithms
size_t x86_64_gen_vpopcntb_zmm_zmm    ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vpopcntw_zmm_zmm    ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vpshufbitqmb_k_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );

// AVX-512VPOPCNTDQ - Population Count
size_t x86_64_gen_vpopcntd_zmm_zmm    ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_vpopcntq_zmm_zmm    ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );

// Additional AVX-512F Memory Operations
size_t x86_64_gen_vmovaps_zmm_m512    ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, enum x86_64_reg_e _base, int32_t disp );
size_t x86_64_gen_vmovaps_m512_zmm    ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _base, int32_t disp, enum x86_64_reg_e _reg );
size_t x86_64_gen_vgatherdps_zmm_vm32 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, enum x86_64_reg_e _base, enum x86_64_reg_e _index, uint8_t scale );
size_t x86_64_gen_vscatterdps_vm32_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _base, enum x86_64_reg_e _index, uint8_t scale, enum x86_64_reg_e _reg );

// AVX-512F Mask Operations
size_t x86_64_gen_kmovw              ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_kmovb              ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_kmovd              ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_kmovq              ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_kandw              ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_kandn              ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_kunpckbw           ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );

// AVX-512F Round Operations
size_t x86_64_gen_vrndscaleps_zmm_zmm_imm8 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, uint8_t imm8 );
size_t x86_64_gen_vrndscalepd_zmm_zmm_imm8 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, uint8_t imm8 );

// AVX-512F Permute Operations
size_t x86_64_gen_vpermps_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vpermpd_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vpermt2ps_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );
size_t x86_64_gen_vpermi2ps_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 );

// Flow control and branches 
size_t x86_64_gen_jmp_imm32    ( x86_64_code_gen *p_code_gen, int32_t imm32 );
size_t x86_64_gen_je_imm32     ( x86_64_code_gen *p_code_gen, int32_t imm32 );
size_t x86_64_gen_jne_imm32    ( x86_64_code_gen *p_code_gen, int32_t imm32 );
size_t x86_64_gen_jg_imm32     ( x86_64_code_gen *p_code_gen, int32_t imm32 );
size_t x86_64_gen_jge_imm32    ( x86_64_code_gen *p_code_gen, int32_t imm32 );
size_t x86_64_gen_jl_imm32     ( x86_64_code_gen *p_code_gen, int32_t imm32 );
size_t x86_64_gen_jle_imm32    ( x86_64_code_gen *p_code_gen, int32_t imm32 );
size_t x86_64_gen_ja_imm32     ( x86_64_code_gen *p_code_gen, int32_t imm32 ); // Above (unsigned)
size_t x86_64_gen_jae_imm32    ( x86_64_code_gen *p_code_gen, int32_t imm32 );
size_t x86_64_gen_jb_imm32     ( x86_64_code_gen *p_code_gen, int32_t imm32 ); // Below (unsigned)
size_t x86_64_gen_jbe_imm32    ( x86_64_code_gen *p_code_gen, int32_t imm32 );

// Conditional moves
size_t x86_64_gen_cmove_r64_r64  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_cmovne_r64_r64 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_cmovg_r64_r64  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_cmovge_r64_r64 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_cmovl_r64_r64  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_cmovle_r64_r64 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );

// Stack frame and function prologue/epilogue
size_t x86_64_gen_enter        ( x86_64_code_gen *p_code_gen, uint16_t stack_size, uint8_t nesting_level );
size_t x86_64_gen_leave        ( x86_64_code_gen *p_code_gen );
size_t x86_64_gen_push_imm32   ( x86_64_code_gen *p_code_gen, int32_t imm32 );
size_t x86_64_gen_pushfq       ( x86_64_code_gen *p_code_gen );
size_t x86_64_gen_popfq        ( x86_64_code_gen *p_code_gen );

// Memory access patterns
size_t x86_64_gen_lea_r64_m     ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, enum x86_64_reg_e _base, int32_t disp );
size_t x86_64_gen_mov_r64_m64   ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, enum x86_64_reg_e _base, int32_t disp );
size_t x86_64_gen_mov_m64_r64   ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _base, int32_t disp, enum x86_64_reg_e _reg );
size_t x86_64_gen_mov_r32_m32   ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, enum x86_64_reg_e _base, int32_t disp );
size_t x86_64_gen_mov_m32_r32   ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _base, int32_t disp, enum x86_64_reg_e _reg );
size_t x86_64_gen_movsx_r64_m8  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, enum x86_64_reg_e _base, int32_t disp );
size_t x86_64_gen_movsx_r64_m16 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, enum x86_64_reg_e _base, int32_t disp );
size_t x86_64_gen_movsx_r64_m32 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, enum x86_64_reg_e _base, int32_t disp );
size_t x86_64_gen_movzx_r64_m8  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, enum x86_64_reg_e _base, int32_t disp );
size_t x86_64_gen_movzx_r64_m16 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, enum x86_64_reg_e _base, int32_t disp );

// Additional arithmetic operations
size_t x86_64_gen_imul_r64_r64_imm32 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, int32_t imm32 );
size_t x86_64_gen_add_r64_imm32      ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, int32_t imm32 );
size_t x86_64_gen_sub_r64_imm32      ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, int32_t imm32 );
size_t x86_64_gen_cmp_r64_imm32      ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, int32_t imm32 );

// Function call helpers
size_t x86_64_gen_call_imm32   ( x86_64_code_gen *p_code_gen, int32_t imm32 );
size_t x86_64_gen_call_indirect ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, int32_t disp );

// Bit manipulation
size_t x86_64_gen_bsf_r64_r64  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 ); // Bit Scan Forward
size_t x86_64_gen_bsr_r64_r64  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 ); // Bit Scan Reverse
size_t x86_64_gen_bt_r64_imm8  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, uint8_t bit ); // Bit Test
size_t x86_64_gen_bts_r64_imm8 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, uint8_t bit ); // Bit Test and Set

// String operations
size_t x86_64_gen_movsb        ( x86_64_code_gen *p_code_gen );
size_t x86_64_gen_movsw        ( x86_64_code_gen *p_code_gen );
size_t x86_64_gen_movsd        ( x86_64_code_gen *p_code_gen );
size_t x86_64_gen_movsq        ( x86_64_code_gen *p_code_gen );
size_t x86_64_gen_rep_movsb    ( x86_64_code_gen *p_code_gen );
size_t x86_64_gen_rep_movsw    ( x86_64_code_gen *p_code_gen );
size_t x86_64_gen_rep_movsd    ( x86_64_code_gen *p_code_gen );
size_t x86_64_gen_rep_movsq    ( x86_64_code_gen *p_code_gen );

// Atomic operations
size_t x86_64_gen_lock_xadd_m64_r64 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _base, int32_t disp, enum x86_64_reg_e _reg );
size_t x86_64_gen_lock_xchg_m64_r64 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _base, int32_t disp, enum x86_64_reg_e _reg );
size_t x86_64_gen_lock_cmpxchg_m64_r64 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _base, int32_t disp, enum x86_64_reg_e _reg );

// System operations
size_t x86_64_gen_rdtsc        ( x86_64_code_gen *p_code_gen );
size_t x86_64_gen_pause        ( x86_64_code_gen *p_code_gen );
size_t x86_64_gen_mfence       ( x86_64_code_gen *p_code_gen );
size_t x86_64_gen_lfence       ( x86_64_code_gen *p_code_gen );
size_t x86_64_gen_sfence       ( x86_64_code_gen *p_code_gen );
