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
enum x86_64_reg_e
{
    RAX = 0b000,
    RCX = 0b001,
    RDX = 0b010,
    RBX = 0b011,
    RSP = 0b100,
    RBP = 0b101,
    RSI = 0b110,    
    RDI = 0b111
};

// Structure definitions
struct x86_64_code_gen_s
{
    size_t         size;
    void          *p_base;
    unsigned char *p_offset;
};

// Type definitions
typedef struct x86_64_code_gen_s x86_64_code_gen;

// Constructors
int x86_64_code_gen_construct ( x86_64_code_gen **pp_x86_64_code_gen, void *p_out, size_t size );

// Stack
size_t x86_64_gen_push_reg ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg );
size_t x86_64_gen_pop_reg  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg );

// Bitwise
size_t x86_64_gen_and_reg_reg  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_or_reg_reg   ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_xor_reg_reg  ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_test_reg_reg ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_not_reg      ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg );
size_t x86_64_gen_shl_reg_imm8 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, unsigned char imm8 );
size_t x86_64_gen_shr_reg_imm8 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, unsigned char imm8 );
size_t x86_64_gen_rol_reg_imm8 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, unsigned char imm8 );
size_t x86_64_gen_ror_reg_imm8 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, unsigned char imm8 );

// Arithmetic
size_t x86_64_gen_add_reg_reg ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
size_t x86_64_gen_sub_reg_reg ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );
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
size_t x86_64_gen_mov_reg_reg   ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 );

// Misc
size_t x86_64_gen_nop ( x86_64_code_gen *p_code_gen );
