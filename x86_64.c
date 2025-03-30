/** !
 * x86_64 code generator 
 * 
 * @file x86_64.c
 * 
 * @author Jacob Smith 
 */

// Header
#include <code_gen/x86_64.h>

// Preprocessor macros
#define X86_64_REG_QUANTITY 8

// Function definitions

///////////
// Stack //
///////////
size_t x86_64_gen_push_reg ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg )
{

    // Success
    return pack_pack(p_code_gen->p_offset, "%i8",
        0x50 | _reg
    );
}

size_t x86_64_gen_pop_reg ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg )
{

    // Success
    return pack_pack(p_code_gen->p_offset, "%i8",
        0x58 | _reg
    );
}

/////////////
// Bitwise //
/////////////
size_t x86_64_gen_and_reg_reg ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 )
{

    // Success
    return pack_pack(p_code_gen->p_offset, "%3i8",
        0x48,
        0x21,
        0xC0 | _reg1 << 3 | _reg2
    );
}

size_t x86_64_gen_or_reg_reg ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 )
{

    // Success
    return pack_pack(p_code_gen->p_offset, "%3i8",
        0x48,
        0x09,
        0xC0 | _reg1 << 3 | _reg2
    );
}

size_t x86_64_gen_xor_reg_reg ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 )
{
    
    // Success
    return pack_pack(p_code_gen->p_offset, "%3i8",
        0x48,
        0x31,
        0xC0 | _reg1 << 3 | _reg2
    );
}

size_t x86_64_gen_test_reg_reg ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 )
{
    
    // Success
    return pack_pack(p_code_gen->p_offset, "%3i8",
        0x48,
        0x85,
        0xC0 | _reg1 << 3 | _reg2
    );
}

size_t x86_64_gen_not_reg ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg )
{

    // Success
    return pack_pack(p_code_gen->p_offset, "%3i8",
        0x48,
        0xF7,
        0xD0 | _reg
    );
}

size_t x86_64_gen_shl_reg_imm8 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, unsigned char imm8 )
{

    // Success
    return pack_pack(p_code_gen->p_offset, "%4i8",
        0x48,
        0xC1,
        0xE0 | _reg,
        imm8
    );
}

size_t x86_64_gen_shr_reg_imm8 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, unsigned char imm8 )
{

    // Success
    return pack_pack(p_code_gen->p_offset, "%4i8",
        0x48,
        0xC1,
        0xE8 | _reg,
        imm8
    );
}

size_t x86_64_gen_rol_reg_imm8 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, unsigned char imm8 )
{

    // Success
    return pack_pack(p_code_gen->p_offset, "%4i8",
        0x48,
        0xC1,
        0xC0 | _reg,
        imm8
    );
}

size_t x86_64_gen_ror_reg_imm8 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, unsigned char imm8 )
{

    // Success
    return pack_pack(p_code_gen->p_offset, "%4i8",
        0x48,
        0xC1,
        0xC8 | _reg,
        imm8
    );
}

////////////////
// Arithmetic //
////////////////
size_t x86_64_gen_add_reg_reg ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 )
{
    
    // Success
    return pack_pack(p_code_gen->p_offset, "%3i8",
        0x48,
        0x01,
        0xC0 | _reg1 << 3 | _reg2
    );
}

size_t x86_64_gen_sub_reg_reg ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 )
{
    
    // Success
    return pack_pack(p_code_gen->p_offset, "%3i8",
        0x48,
        0x29,
        0xC0 | _reg1 << 3 | _reg2
    );
}

size_t x86_64_gen_neg_reg ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg )
{
    
    // Success
    return pack_pack(p_code_gen->p_offset, "%3i8",
        0x48,
        0xF7,
        0xD8 | _reg
    );
}

size_t x86_64_gen_mul_reg ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg )
{
    
    // Success
    return pack_pack(p_code_gen->p_offset, "%3i8",
        0x48,
        0xF7,
        0xE0 | _reg
    );
}

size_t x86_64_gen_imul_reg ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg )
{
    
    // Success
    return pack_pack(p_code_gen->p_offset, "%3i8",
        0x48,
        0xF7,
        0xE8 | _reg
    );
}

size_t x86_64_gen_div_reg ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg )
{
    
    // Success
    return pack_pack(p_code_gen->p_offset, "%3i8",
        0x48,
        0xF7,
        0xF0 | _reg
    );
}

size_t x86_64_gen_idiv_reg ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg )
{
    
    // Success
    return pack_pack(p_code_gen->p_offset, "%3i8",
        0x48,
        0xF7,
        0xF8 | _reg
    );
}

size_t x86_64_gen_inc_reg ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg )
{

    // Success
    return pack_pack(p_code_gen->p_offset, "%3i8",
        0x48,
        0xFF,
        0xC0 | _reg
    );
}

size_t x86_64_gen_dec_reg ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg )
{

    // Success
    return pack_pack(p_code_gen->p_offset, "%3i8",
        0x48,
        0xFF,
        0xC8 | _reg
    );
}

//////////////////
// Flow Control //
//////////////////
size_t x86_64_gen_jmp_reg ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg )
{
    
    // Success
    return pack_pack(p_code_gen->p_offset, "%2i8",
        0xFF,
        0xE0 | _reg
    );
}

size_t x86_64_gen_call_reg ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg )
{
    
    // Success
    return pack_pack(p_code_gen->p_offset, "%2i8",
        0xFF,
        0xD0 | _reg
    );
}

size_t x86_64_gen_ret ( x86_64_code_gen *p_code_gen )
{

    // Success
    return pack_pack(p_code_gen->p_offset, "%i8", 0xC3);
}

//////////
// Move //
//////////
size_t x86_64_gen_mov_reg_imm64 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, long long imm64 )
{
    
    // Success
    return pack_pack(p_code_gen->p_offset, "%2i8%i64",
        0x48,
        0xB8 | _reg,
        imm64
    );
}

size_t x86_64_gen_mov_reg_reg ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 )
{
    
    // Success
    return pack_pack(p_code_gen->p_offset, "%3i8",
        0x48,
        0x89,
        0xC0 | _reg1 << 3 | _reg2
    );
}

//////////
// Misc //
//////////
size_t x86_64_gen_nop ( x86_64_code_gen *p_code_gen )
{

    // Success
    return pack_pack(p_code_gen->p_offset, "%i8", 0x90);
}

// Function definitions
int x86_64_code_gen_construct ( x86_64_code_gen **pp_code_gen, void *p_out, size_t size )
{

    // Argument check
    if ( pp_code_gen == (void *) 0 ) goto no_x86_64_code_gen;
    if ( size        ==          0 ) goto no_size;

    // Initialized data
    x86_64_code_gen *p_code_gen = malloc(size + sizeof(x86_64_code_gen));

    // Error check
    if ( p_code_gen == (void *) 0 ) goto no_mem;

    // Store the size of the pool
    p_code_gen->size = size;

    // Allocate an executable page
    p_code_gen->p_base = mmap(NULL, 8192, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    // Error check
    if ( (void *) -1 == p_code_gen->p_base) goto no_mem; 
    
    // Store the offset
    p_code_gen->p_offset = p_code_gen->p_base;

    ///////////////////////////
    // Assemble the function //
    ///////////////////////////
    {

        // inc
        for (size_t i = 0; i < X86_64_REG_QUANTITY; i++)
            p_code_gen->p_offset += x86_64_gen_inc_reg (p_code_gen, (enum x86_64_reg_e) i);
        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
            
        // dec
        for (size_t i = 0; i < X86_64_REG_QUANTITY; i++)
            p_code_gen->p_offset += x86_64_gen_dec_reg (p_code_gen, (enum x86_64_reg_e) i);
        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
        
        // push
        for (size_t i = 0; i < X86_64_REG_QUANTITY; i++)
            p_code_gen->p_offset += x86_64_gen_push_reg(p_code_gen, (enum x86_64_reg_e) i);
        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
        
        // pop
        for (size_t i = 0; i < X86_64_REG_QUANTITY; i++)
            p_code_gen->p_offset += x86_64_gen_pop_reg (p_code_gen, (enum x86_64_reg_e) i);
        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
    }

    /////////////
    // Bitwise //
    /////////////
    {

        // not
        for (size_t i = 0; i < X86_64_REG_QUANTITY; i++)
            p_code_gen->p_offset += x86_64_gen_not_reg (p_code_gen, (enum x86_64_reg_e) i);
        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
            
        // and
        for (size_t i = 0; i < X86_64_REG_QUANTITY; i++)
            for (size_t j = 0; j < X86_64_REG_QUANTITY; j++)
                p_code_gen->p_offset += x86_64_gen_and_reg_reg (p_code_gen, (enum x86_64_reg_e) i, (enum x86_64_reg_e) j);
        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
        
        // or
        for (size_t i = 0; i < X86_64_REG_QUANTITY; i++)
            for (size_t j = 0; j < X86_64_REG_QUANTITY; j++)
                p_code_gen->p_offset += x86_64_gen_or_reg_reg (p_code_gen, (enum x86_64_reg_e) i, (enum x86_64_reg_e) j);
        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
        
        // xor
        for (size_t i = 0; i < X86_64_REG_QUANTITY; i++)
            for (size_t j = 0; j < X86_64_REG_QUANTITY; j++)
                p_code_gen->p_offset += x86_64_gen_xor_reg_reg (p_code_gen, (enum x86_64_reg_e) i, (enum x86_64_reg_e) j);
        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
        
        // test
        for (size_t i = 0; i < X86_64_REG_QUANTITY; i++)
            for (size_t j = 0; j < X86_64_REG_QUANTITY; j++)
                p_code_gen->p_offset += x86_64_gen_test_reg_reg (p_code_gen, (enum x86_64_reg_e) i, (enum x86_64_reg_e) j);
        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
        
        // shl
        for (size_t i = 0; i < X86_64_REG_QUANTITY; i++)
            p_code_gen->p_offset += x86_64_gen_shl_reg_imm8 (p_code_gen, (enum x86_64_reg_e) i, i);
        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
        
        // shr
        for (size_t i = 0; i < X86_64_REG_QUANTITY; i++)
            p_code_gen->p_offset += x86_64_gen_shr_reg_imm8 (p_code_gen, (enum x86_64_reg_e) i, i);
        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
        
        // rol
        for (size_t i = 0; i < X86_64_REG_QUANTITY; i++)
            p_code_gen->p_offset += x86_64_gen_rol_reg_imm8 (p_code_gen, (enum x86_64_reg_e) i, i);
        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);

        // ror
        for (size_t i = 0; i < X86_64_REG_QUANTITY; i++)
            p_code_gen->p_offset += x86_64_gen_ror_reg_imm8 (p_code_gen, (enum x86_64_reg_e) i, i);
        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
    }
    
    ////////////////
    // Arithmetic //
    ////////////////
    {

        // add
        for (size_t i = 0; i < X86_64_REG_QUANTITY; i++)
            for (size_t j = 0; j < X86_64_REG_QUANTITY; j++)
                p_code_gen->p_offset += x86_64_gen_add_reg_reg (p_code_gen, (enum x86_64_reg_e) i, (enum x86_64_reg_e) j);
        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
        
        // sub
        for (size_t i = 0; i < X86_64_REG_QUANTITY; i++)
            for (size_t j = 0; j < X86_64_REG_QUANTITY; j++)
                p_code_gen->p_offset += x86_64_gen_sub_reg_reg (p_code_gen, (enum x86_64_reg_e) i, (enum x86_64_reg_e) j);
        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
        
        // neg
        for (size_t i = 0; i < X86_64_REG_QUANTITY; i++)
            p_code_gen->p_offset += x86_64_gen_neg_reg (p_code_gen, (enum x86_64_reg_e) i);
        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
        
        // mul
        for (size_t i = 0; i < X86_64_REG_QUANTITY; i++)
            p_code_gen->p_offset += x86_64_gen_mul_reg (p_code_gen, (enum x86_64_reg_e) i);
        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
        
        // imul
        for (size_t i = 0; i < X86_64_REG_QUANTITY; i++)
            p_code_gen->p_offset += x86_64_gen_imul_reg (p_code_gen, (enum x86_64_reg_e) i);
        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
        
        // div
        for (size_t i = 0; i < X86_64_REG_QUANTITY; i++)
            p_code_gen->p_offset += x86_64_gen_div_reg (p_code_gen, (enum x86_64_reg_e) i);
        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);

        // idiv
        for (size_t i = 0; i < X86_64_REG_QUANTITY; i++)
            p_code_gen->p_offset += x86_64_gen_idiv_reg (p_code_gen, (enum x86_64_reg_e) i);
        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
    }

    //////////
    // Jump //
    //////////
    {
        
        // jmp
        for (size_t i = 0; i < X86_64_REG_QUANTITY; i++)
            p_code_gen->p_offset += x86_64_gen_jmp_reg (p_code_gen, (enum x86_64_reg_e) i);
        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
        
        // call
        for (size_t i = 0; i < X86_64_REG_QUANTITY; i++)
            p_code_gen->p_offset += x86_64_gen_call_reg (p_code_gen, (enum x86_64_reg_e) i);

        // ret
        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
    }

    //////////
    // Misc //
    //////////
    {
        // nop
        p_code_gen->p_offset += x86_64_gen_nop(p_code_gen);
        
        // ret
        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
    }

    //////////
    // Move //
    //////////
    {
       
        // mov
        for (size_t i = 0; i < X86_64_REG_QUANTITY; i++)
            p_code_gen->p_offset += x86_64_gen_mov_reg_imm64 (p_code_gen, (enum x86_64_reg_e) i, (long long) i);
        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
            
        // mov
        for (size_t i = 0; i < X86_64_REG_QUANTITY; i++)
            p_code_gen->p_offset += x86_64_gen_mov_reg_imm64 (p_code_gen, (enum x86_64_reg_e) i, (long long) -i);
        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
        // mov
        for (size_t i = 0; i < X86_64_REG_QUANTITY; i++)
            for (size_t j = 0; j < X86_64_REG_QUANTITY; j++)
                p_code_gen->p_offset += x86_64_gen_mov_reg_reg (p_code_gen, (enum x86_64_reg_e) i, (enum x86_64_reg_e) j);
        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
        
    }

    // Update page permissions 
    if ( -1 == mprotect(p_code_gen->p_base, (size_t)sysconf(_SC_PAGESIZE), PROT_READ | PROT_EXEC) ) goto failed_to_update_permissions;

    // Set the size
    p_code_gen->size = ((size_t)p_code_gen->p_offset - (size_t)p_code_gen->p_base);

    // Output (for ndisasm) 
    if ( p_out )
        memcpy(p_out, p_code_gen->p_base, p_code_gen->size);

    // Store the allocator
    *pp_code_gen = p_code_gen;

    // Success
    return 1;

    // Error checking
    {
        
        // Argument errors
        {
            no_x86_64_code_gen:
                #ifndef NDEBUG
                    log_error("[allocator] [linear] Null pointer provided for parameter \"p_code_gen\" in call to function \"%s\"\n", __FUNCTION__);
                #endif

                // Error
                return 0;

            no_size:
                #ifndef NDEBUG
                    log_error("[allocator] [linear] Null pointer provided for parameter \"size\" in call to function \"%s\"\n", __FUNCTION__);
                #endif

                // Error
                return 0;
        }

        // POSIX errors
        {
            failed_to_update_permissions:
                #ifndef NDEBUG
                    log_error("[sys] [mman] Call to \"mprotect\" returned an erroneous value in call to function \"%s\"\n", __FUNCTION__);
                #endif

                // Error
                return 0;
        }

        // Standard library
        {
            no_mem:
                #ifndef NDEBUG
                    log_error("[Standard library] Failed to allocate memory in call to function \"%s\"\n", __FUNCTION__);
                #endif

                // Error
                return 0;
        }
    }
}
