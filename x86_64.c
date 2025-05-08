/** !
 * x86_64 code generator 
 * 
 * @file x86_64.c
 * 
 * @author Jacob Smith 
 */

// Header
#include <code_gen/x86_64.h>

// Function definitions

// Constructors
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
    
    /*
    ///////////////////////////
    // Assemble the function //
    ///////////////////////////
    {

        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
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
                p_code_gen->p_offset += x86_64_gen_and_r64_r64 (p_code_gen, (enum x86_64_reg_e) i, (enum x86_64_reg_e) j);
        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
        
        // or
        for (size_t i = 0; i < X86_64_REG_QUANTITY; i++)
            for (size_t j = 0; j < X86_64_REG_QUANTITY; j++)
                p_code_gen->p_offset += x86_64_gen_or_r64_r64 (p_code_gen, (enum x86_64_reg_e) i, (enum x86_64_reg_e) j);
        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
        
        // xor
        for (size_t i = 0; i < X86_64_REG_QUANTITY; i++)
            for (size_t j = 0; j < X86_64_REG_QUANTITY; j++)
                p_code_gen->p_offset += x86_64_gen_xor_r64_r64 (p_code_gen, (enum x86_64_reg_e) i, (enum x86_64_reg_e) j);
        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
        
        // test
        for (size_t i = 0; i < X86_64_REG_QUANTITY; i++)
            for (size_t j = 0; j < X86_64_REG_QUANTITY; j++)
                p_code_gen->p_offset += x86_64_gen_test_r64_r64 (p_code_gen, (enum x86_64_reg_e) i, (enum x86_64_reg_e) j);
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

        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
        
        // add
        for (size_t i = 0; i < X86_64_REG_QUANTITY; i++)
            for (size_t j = 0; j < X86_64_REG_QUANTITY; j++)
                p_code_gen->p_offset += x86_64_gen_add_r64_r64 (p_code_gen, (enum x86_64_reg_e) i, (enum x86_64_reg_e) j);
        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
        
        // sub
        for (size_t i = 0; i < X86_64_REG_QUANTITY; i++)
            for (size_t j = 0; j < X86_64_REG_QUANTITY; j++)
                p_code_gen->p_offset += x86_64_gen_sub_r64_r64 (p_code_gen, (enum x86_64_reg_e) i, (enum x86_64_reg_e) j);
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
                p_code_gen->p_offset += x86_64_gen_mov_r64_r64 (p_code_gen, (enum x86_64_reg_e) i, (enum x86_64_reg_e) j);
        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
        
    }
    */

    // // Update page permissions 
    // if ( -1 == mprotect(p_code_gen->p_base, (size_t)sysconf(_SC_PAGESIZE), PROT_READ | PROT_EXEC) ) goto failed_to_update_permissions;

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

int x86_64_code_gen_node_construct ( x86_64_code_gen *p_code_gen, char *instruction, char *op1, char *op2, char *op3 ) 
{

    // Initialized data
    x86_64_op _op1, _op2, _op3;

    // Parse operand 1 
    if ( op1 )
    {
             if ( 0 == strncmp(op1, "RAX" , 3) ) _op1 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RAX };
        else if ( 0 == strncmp(op1, "RCX" , 3) ) _op1 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RCX };
        else if ( 0 == strncmp(op1, "RDX" , 3) ) _op1 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RDX };
        else if ( 0 == strncmp(op1, "RBX" , 3) ) _op1 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RBX };
        else if ( 0 == strncmp(op1, "RSP" , 3) ) _op1 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RSP };
        else if ( 0 == strncmp(op1, "RBP" , 3) ) _op1 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RBP };
        else if ( 0 == strncmp(op1, "RSI" , 3) ) _op1 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RSI };
        else if ( 0 == strncmp(op1, "RDI" , 3) ) _op1 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RDI };

        else if ( 0 == strncmp(op1, "XMM0", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM0 };
        else if ( 0 == strncmp(op1, "XMM1", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM1 };
        else if ( 0 == strncmp(op1, "XMM2", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM2 };
        else if ( 0 == strncmp(op1, "XMM3", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM3 };
        else if ( 0 == strncmp(op1, "XMM4", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM4 };
        else if ( 0 == strncmp(op1, "XMM5", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM5 };
        else if ( 0 == strncmp(op1, "XMM6", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM6 };
        else if ( 0 == strncmp(op1, "XMM7", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM7 };

        else if ( 0 == strncmp(op1, "YMM0", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM0 };
        else if ( 0 == strncmp(op1, "YMM1", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM1 };
        else if ( 0 == strncmp(op1, "YMM2", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM2 };
        else if ( 0 == strncmp(op1, "YMM3", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM3 };
        else if ( 0 == strncmp(op1, "YMM4", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM4 };
        else if ( 0 == strncmp(op1, "YMM5", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM5 };
        else if ( 0 == strncmp(op1, "YMM6", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM6 };
        else if ( 0 == strncmp(op1, "YMM7", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM7 };

        else if ( 0 == strncmp(op1, "ZMM0", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM0 };
        else if ( 0 == strncmp(op1, "ZMM1", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM1 };
        else if ( 0 == strncmp(op1, "ZMM2", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM2 };
        else if ( 0 == strncmp(op1, "ZMM3", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM3 };
        else if ( 0 == strncmp(op1, "ZMM4", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM4 };
        else if ( 0 == strncmp(op1, "ZMM5", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM5 };
        else if ( 0 == strncmp(op1, "ZMM6", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM6 };
        else if ( 0 == strncmp(op1, "ZMM7", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM7 };

        else                                     _op1 = (x86_64_op) { ._type = X86_64_IMM64  , ._imm64 = atoi(op1) };
    }

    // Parse operand 2 
    if ( op2 )
    {
             if ( 0 == strncmp(op2, "RAX" , 3) ) _op2 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RAX };
        else if ( 0 == strncmp(op2, "RCX" , 3) ) _op2 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RCX };
        else if ( 0 == strncmp(op2, "RDX" , 3) ) _op2 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RDX };
        else if ( 0 == strncmp(op2, "RBX" , 3) ) _op2 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RBX };
        else if ( 0 == strncmp(op2, "RSP" , 3) ) _op2 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RSP };
        else if ( 0 == strncmp(op2, "RBP" , 3) ) _op2 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RBP };
        else if ( 0 == strncmp(op2, "RSI" , 3) ) _op2 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RSI };
        else if ( 0 == strncmp(op2, "RDI" , 3) ) _op2 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RDI };

        else if ( 0 == strncmp(op2, "XMM0", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM0 };
        else if ( 0 == strncmp(op2, "XMM1", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM1 };
        else if ( 0 == strncmp(op2, "XMM2", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM2 };
        else if ( 0 == strncmp(op2, "XMM3", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM3 };
        else if ( 0 == strncmp(op2, "XMM4", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM4 };
        else if ( 0 == strncmp(op2, "XMM5", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM5 };
        else if ( 0 == strncmp(op2, "XMM6", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM6 };
        else if ( 0 == strncmp(op2, "XMM7", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM7 };

        else if ( 0 == strncmp(op2, "YMM0", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM0 };
        else if ( 0 == strncmp(op2, "YMM1", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM1 };
        else if ( 0 == strncmp(op2, "YMM2", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM2 };
        else if ( 0 == strncmp(op2, "YMM3", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM3 };
        else if ( 0 == strncmp(op2, "YMM4", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM4 };
        else if ( 0 == strncmp(op2, "YMM5", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM5 };
        else if ( 0 == strncmp(op2, "YMM6", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM6 };
        else if ( 0 == strncmp(op2, "YMM7", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM7 };

        else if ( 0 == strncmp(op2, "ZMM0", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM0 };
        else if ( 0 == strncmp(op2, "ZMM1", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM1 };
        else if ( 0 == strncmp(op2, "ZMM2", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM2 };
        else if ( 0 == strncmp(op2, "ZMM3", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM3 };
        else if ( 0 == strncmp(op2, "ZMM4", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM4 };
        else if ( 0 == strncmp(op2, "ZMM5", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM5 };
        else if ( 0 == strncmp(op2, "ZMM6", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM6 };
        else if ( 0 == strncmp(op2, "ZMM7", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM7 };

        else                                     _op2 = (x86_64_op) { ._type = X86_64_IMM64  , ._imm64 = atoi(op2) };

    }

    // Parse operand 3 
    if ( op3 )
    {
             if ( 0 == strncmp(op3, "RAX" , 3) ) _op3 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RAX };
        else if ( 0 == strncmp(op3, "RCX" , 3) ) _op3 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RCX };
        else if ( 0 == strncmp(op3, "RDX" , 3) ) _op3 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RDX };
        else if ( 0 == strncmp(op3, "RBX" , 3) ) _op3 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RBX };
        else if ( 0 == strncmp(op3, "RSP" , 3) ) _op3 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RSP };
        else if ( 0 == strncmp(op3, "RBP" , 3) ) _op3 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RBP };
        else if ( 0 == strncmp(op3, "RSI" , 3) ) _op3 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RSI };
        else if ( 0 == strncmp(op3, "RDI" , 3) ) _op3 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RDI };

        else if ( 0 == strncmp(op3, "XMM0", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM0 };
        else if ( 0 == strncmp(op3, "XMM1", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM1 };
        else if ( 0 == strncmp(op3, "XMM2", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM2 };
        else if ( 0 == strncmp(op3, "XMM3", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM3 };
        else if ( 0 == strncmp(op3, "XMM4", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM4 };
        else if ( 0 == strncmp(op3, "XMM5", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM5 };
        else if ( 0 == strncmp(op3, "XMM6", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM6 };
        else if ( 0 == strncmp(op3, "XMM7", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM7 };

        else if ( 0 == strncmp(op3, "YMM0", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM0 };
        else if ( 0 == strncmp(op3, "YMM1", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM1 };
        else if ( 0 == strncmp(op3, "YMM2", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM2 };
        else if ( 0 == strncmp(op3, "YMM3", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM3 };
        else if ( 0 == strncmp(op3, "YMM4", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM4 };
        else if ( 0 == strncmp(op3, "YMM5", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM5 };
        else if ( 0 == strncmp(op3, "YMM6", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM6 };
        else if ( 0 == strncmp(op3, "YMM7", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM7 };

        else if ( 0 == strncmp(op3, "ZMM0", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM0 };
        else if ( 0 == strncmp(op3, "ZMM1", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM1 };
        else if ( 0 == strncmp(op3, "ZMM2", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM2 };
        else if ( 0 == strncmp(op3, "ZMM3", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM3 };
        else if ( 0 == strncmp(op3, "ZMM4", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM4 };
        else if ( 0 == strncmp(op3, "ZMM5", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM5 };
        else if ( 0 == strncmp(op3, "ZMM6", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM6 };
        else if ( 0 == strncmp(op3, "ZMM7", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM7 };

        else                                     _op3 = (x86_64_op) { ._type = X86_64_IMM64  , ._imm64 = atoi(op3) };
    }

    // No operands
    if ( !( op1 && op2 && op3 ) )
    {
             if ( 0 == strcmp(instruction, "RET")     ) p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
        else if ( 0 == strcmp(instruction, "NOP")     ) p_code_gen->p_offset += x86_64_gen_nop(p_code_gen);
        else if ( 0 == strcmp(instruction, "SYSCALL") ) p_code_gen->p_offset += x86_64_gen_syscall(p_code_gen);
    }

    // One operand
    if ( op1 && !( op2 && op3 ) )
    {
        if ( _op1._type == X86_64_REG_64 )
        {
                 if ( 0 == strcmp(instruction, "PUSH") ) p_code_gen->p_offset += x86_64_gen_push_reg(p_code_gen, _op1._reg);
            else if ( 0 == strcmp(instruction, "POP")  ) p_code_gen->p_offset += x86_64_gen_pop_reg(p_code_gen, _op1._reg);
            else if ( 0 == strcmp(instruction, "INC")  ) p_code_gen->p_offset += x86_64_gen_inc_reg(p_code_gen, _op1._reg);
            else if ( 0 == strcmp(instruction, "DEC")  ) p_code_gen->p_offset += x86_64_gen_dec_reg(p_code_gen, _op1._reg);
        } 
    }
    
    // Two operand
    if ( op1 && op2 && !op3 )
    {

        // reg, reg
        if ( _op1._type == X86_64_REG_64 && _op2._type == X86_64_REG_64 )
        {
                 if ( 0 == strcmp(instruction, "MOV")  ) p_code_gen->p_offset += x86_64_gen_mov_r64_r64(p_code_gen, _op1._reg, _op2._reg);
            else if ( 0 == strcmp(instruction, "AND")  ) p_code_gen->p_offset += x86_64_gen_and_r64_r64(p_code_gen, _op1._reg, _op2._reg);
            else if ( 0 == strcmp(instruction, "OR")   ) p_code_gen->p_offset += x86_64_gen_or_r64_r64(p_code_gen, _op1._reg, _op2._reg);
            else if ( 0 == strcmp(instruction, "XOR")  ) p_code_gen->p_offset += x86_64_gen_xor_r64_r64(p_code_gen, _op1._reg, _op2._reg);
            else if ( 0 == strcmp(instruction, "TEST") ) p_code_gen->p_offset += x86_64_gen_xor_r64_r64(p_code_gen, _op1._reg, _op2._reg);
            else if ( 0 == strcmp(instruction, "ADD")  ) p_code_gen->p_offset += x86_64_gen_add_r64_r64(p_code_gen, _op1._reg, _op2._reg);
            else if ( 0 == strcmp(instruction, "SUB")  ) p_code_gen->p_offset += x86_64_gen_sub_r64_r64(p_code_gen, _op1._reg, _op2._reg);
        } 

        // reg, imm64
        else if ( _op1._type == X86_64_REG_64 && _op2._type == X86_64_IMM64 )
        {
            if ( 0 == strcmp(instruction, "MOV") ) p_code_gen->p_offset += x86_64_gen_mov_reg_imm64(p_code_gen, _op1._reg, _op2._imm64);
        }

        else if ( _op1._type == X86_64_REG_128 && _op2._type == X86_64_REG_64 )
        {
            if ( 0 == strcmp(instruction, "VMOVDQA") ) p_code_gen->p_offset += x86_64_avx_gen_mov_reg128_reg64(p_code_gen, _op1._reg, _op2._reg);
        }
    }

    // Three operand
    if ( op1 && op2 && op3 )
    {

        // reg, reg, reg
        if ( _op1._type == X86_64_REG_128 && _op2._type == X86_64_REG_128 && _op3._type == X86_64_REG_128 )
        {
                 if ( 0 == strcmp(instruction, "VPADDD") ) p_code_gen->p_offset += x86_64_avx_gen_add_i32x4_reg128_reg128_reg128(p_code_gen, _op1._reg, _op2._reg, _op3._reg);
            else if ( 0 == strcmp(instruction, "VPADDQ") ) p_code_gen->p_offset += x86_64_avx_gen_add_i64x2_reg128_reg128_reg128(p_code_gen, _op1._reg, _op2._reg, _op3._reg);

            else if ( 0 == strcmp(instruction, "VADDPS") ) p_code_gen->p_offset += x86_64_avx_gen_add_f32x4_reg128_reg128_reg128(p_code_gen, _op1._reg, _op2._reg, _op3._reg);
            else if ( 0 == strcmp(instruction, "VSUBPS") ) p_code_gen->p_offset += x86_64_avx_gen_sub_f32x4_reg128_reg128_reg128(p_code_gen, _op1._reg, _op2._reg, _op3._reg);
            else if ( 0 == strcmp(instruction, "VMULPS") ) p_code_gen->p_offset += x86_64_avx_gen_mul_f32x4_reg128_reg128_reg128(p_code_gen, _op1._reg, _op2._reg, _op3._reg);
            else if ( 0 == strcmp(instruction, "VDIVPS") ) p_code_gen->p_offset += x86_64_avx_gen_div_f32x4_reg128_reg128_reg128(p_code_gen, _op1._reg, _op2._reg, _op3._reg);

            else if ( 0 == strcmp(instruction, "VADDPD") ) p_code_gen->p_offset += x86_64_avx_gen_add_f64x2_reg128_reg128_reg128(p_code_gen, _op1._reg, _op2._reg, _op3._reg);
        } 

        // reg, reg, reg
        if ( _op1._type == X86_64_REG_256 && _op2._type == X86_64_REG_256 && _op3._type == X86_64_REG_256 )
        {
                 if ( 0 == strcmp(instruction, "VADDPS") ) p_code_gen->p_offset += x86_64_avx_gen_add_f32x8_reg256_reg256_reg256(p_code_gen, _op1._reg, _op2._reg, _op3._reg);
        } 

    }

    // Success
    return 1;
}

// Stack
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

// Bitwise
size_t x86_64_gen_and_r64_r64 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 )
{

    // Success
    return pack_pack(p_code_gen->p_offset, "%3i8",
        0x48,
        0x21,
        0xC0 | (_reg2 << 3) | _reg1
    );
}

size_t x86_64_gen_or_r64_r64 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 )
{

    // Success
    return pack_pack(p_code_gen->p_offset, "%3i8",
        0x48,
        0x09,
        0xC0 | (_reg2 << 3) | _reg1
    );
}

size_t x86_64_gen_xor_r64_r64 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 )
{
    
    // Success
    return pack_pack(p_code_gen->p_offset, "%3i8",
        0x48,
        0x31,
        0xC0 | (_reg2 << 3) | _reg1
    );
}

size_t x86_64_gen_test_r64_r64 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 )
{
    
    // Success
    return pack_pack(p_code_gen->p_offset, "%3i8",
        0x48,
        0x85,
        0xC0 | (_reg2 << 3) | _reg1
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

// Arithmetic
size_t x86_64_gen_add_r64_r64 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 )
{
    
    // Success
    return pack_pack(p_code_gen->p_offset, "%3i8",
        0x48,
        0x01,
        0xC0 | _reg2 << 3 | _reg1
    );
}

size_t x86_64_gen_sub_r64_r64 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 )
{
    
    // Success
    return pack_pack(p_code_gen->p_offset, "%3i8",
        0x48,
        0x29,
        0xC0 | _reg2 << 3 | _reg1
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

// Flow control
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

// Move
size_t x86_64_gen_mov_reg_imm64 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, long long imm64 )
{
    
    // Success
    return pack_pack(p_code_gen->p_offset, "%2i8%i64",
        0x48,
        0xB8 | _reg,
        imm64
    );
}

size_t x86_64_gen_mov_r64_r64 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 )
{
    
    // Success
    return pack_pack(p_code_gen->p_offset, "%3i8",
        0x48,
        0x89,
        0xC0 | _reg2 << 3 | _reg1
    );
}

// Misc
size_t x86_64_gen_nop ( x86_64_code_gen *p_code_gen )
{

    // Success
    return pack_pack(p_code_gen->p_offset, "%i8", 0x90);
}

size_t x86_64_gen_syscall ( x86_64_code_gen *p_code_gen )
{

    // Success
    return pack_pack(p_code_gen->p_offset, "%2i8",
        0x0F,
        0x05
    );
}

// AVX operations
size_t x86_64_avx_gen_mov_reg128_reg64 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 )
{
    // Success
    return pack_pack(p_code_gen->p_offset, "%4i8",
        0xC5,
        0xF9,
        0x6F,
        0xC0 | _reg1 << 3
             | _reg2
    );
}

size_t x86_64_avx_gen_add_i32x4_reg128_reg128_reg128 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 )
{

    unsigned char a = _reg1,
                  b = (~_reg2) & 0b111,
                  c = _reg3;

    // Success
    return pack_pack(p_code_gen->p_offset, "%4i8",
        0xC5,
        0xC1 | b << 3,
        0xFE,
        0xC0 | a << 3
             | c
    );
}

size_t x86_64_avx_gen_add_f32x8_reg256_reg256_reg256 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 )
{

    unsigned char a = _reg1,
                  b = (~_reg2) & 0b111,
                  c = _reg3;

    // Success
    return pack_pack(p_code_gen->p_offset, "%4i8",
        0xC5,
        0xC1 | b << 3,
        0x58,
        0xC0 | a << 3
             | c
    );
}

size_t x86_64_avx_gen_add_i64x2_reg128_reg128_reg128 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 )
{

    unsigned char a = _reg1,
                  b = (~_reg2) & 0b111,
                  c = _reg3;

    // Success
    return pack_pack(p_code_gen->p_offset, "%4i8",
        0xC5,
        0xC0 | b << 3,
        0x58,
        0xC0 | a << 3
             | c
    );
}

size_t x86_64_avx_gen_add_f64x2_reg128_reg128_reg128 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 )
{

    unsigned char a = _reg1,
                  b = (~_reg2) & 0b111,
                  c = _reg3;

    // Success
    return pack_pack(p_code_gen->p_offset, "%4i8",
        0xC5,
        0xC1 | b << 3,
        0x58,
        0xC0 | a << 3
             | c
    );
}

size_t x86_64_avx_gen_add_f32x4_reg128_reg128_reg128 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 )
{

    unsigned char a = _reg1,
                  b = (~_reg2) & 0b111,
                  c = _reg3;

    // Success
    return pack_pack(p_code_gen->p_offset, "%4i8",
        0xC5,
        0xC0 | b << 3,
        0x58,
        0xC0 | a << 3
             | c
    );
}

size_t x86_64_avx_gen_sub_f32x4_reg128_reg128_reg128 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 )
{

    unsigned char a = _reg1,
                  b = (~_reg2) & 0b111,
                  c = _reg3;

    // Success
    return pack_pack(p_code_gen->p_offset, "%4i8",
        0xC5,
        0xC0 | b << 3,
        0x5C,
        0xC0 | a << 3
             | c
    );
}

size_t x86_64_avx_gen_mul_f32x4_reg128_reg128_reg128 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 )
{

    unsigned char a = _reg1,
                  b = (~_reg2) & 0b111,
                  c = _reg3;

    // Success
    return pack_pack(p_code_gen->p_offset, "%4i8",
        0xC5,
        0xC0 | b << 3,
        0x59,
        0xC0 | a << 3
             | c
    );
}

size_t x86_64_avx_gen_div_f32x4_reg128_reg128_reg128 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 )
{

    unsigned char a = _reg1,
                  b = (~_reg2) & 0b111,
                  c = _reg3;

    // Success
    return pack_pack(p_code_gen->p_offset, "%4i8",
        0xC5,
        0xC0 | b << 3,
        0x5E,
        0xC0 | a << 3
             | c
    );
}

// Comparison operations
size_t x86_64_gen_cmp_r64_r64 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 )
{
    return pack_pack(p_code_gen->p_offset, "%3i8",
        0x48,
        0x39,
        0xC0 | (_reg2 << 3) | _reg1
    );
}

// Continue with remaining functions in header order...
// AVX-512 Vector Movement Instructions
size_t x86_64_gen_vmovups_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 )
{
    return pack_pack(p_code_gen->p_offset, "%5i8",
        0x62,
        0xF1,
        0x7C,
        0x48,
        0x10 | (_reg1 << 3) | _reg2
    );
}

size_t x86_64_gen_vmovapd_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 )
{
    return pack_pack(p_code_gen->p_offset, "%5i8",
        0x62,
        0xF1,
        0xFD,
        0x48,
        0x28 | (_reg1 << 3) | _reg2
    );
}

// AVX-512 Arithmetic Operations
size_t x86_64_gen_vaddps_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 )
{
    return pack_pack(p_code_gen->p_offset, "%5i8",
        0x62,
        0xF1,
        0x7C,
        0x48,
        0x58 | (_reg1 << 3) | _reg2
    );
}

size_t x86_64_gen_vsubps_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 )
{
    return pack_pack(p_code_gen->p_offset, "%5i8",
        0x62,
        0xF1,
        0x7C,
        0x48,
        0x5C | (_reg1 << 3) | _reg2
    );
}

// AVX-512 FMA Operations
size_t x86_64_gen_vfmadd132ps_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 )
{
    return pack_pack(p_code_gen->p_offset, "%6i8",
        0x62,
        0xF2,
        0x7D,
        0x48,
        0x98,
        0xC0 | (_reg1 << 3) | _reg2
    );
}

// AVX-512 Comparison Operations
size_t x86_64_gen_vcmpps_k_zmm_zmm_imm8 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, uint8_t imm8 )
{
    return pack_pack(p_code_gen->p_offset, "%6i8",
        0x62,
        0xF1,
        0x7C,
        0x48,
        0xC2,
        imm8
    );
}

// AVX-512 Conversion Operations
size_t x86_64_gen_vcvtps2pd_zmm_ymm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 )
{
    return pack_pack(p_code_gen->p_offset, "%5i8",
        0x62,
        0xF1,
        0x7C,
        0x48,
        0x5A | (_reg1 << 3) | _reg2
    );
}

// AVX-512 Memory Operations
size_t x86_64_gen_vmovaps_zmm_m512 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, enum x86_64_reg_e _base, int32_t disp )
{
    return pack_pack(p_code_gen->p_offset, "%5i8%i32",
        0x62,
        0xF1,
        0x7C,
        0x48,
        0x28 | (_reg << 3) | _base,
        disp
    );
}

size_t x86_64_gen_vmovaps_m512_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _base, int32_t disp, enum x86_64_reg_e _reg )
{
    return pack_pack(p_code_gen->p_offset, "%5i8%i32",
        0x62,
        0xF1,
        0x7C,
        0x48,
        0x29 | (_reg << 3) | _base,
        disp
    );
}

// AVX-512 Gather/Scatter Operations
size_t x86_64_gen_vgatherdps_zmm_vm32 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, enum x86_64_reg_e _base, enum x86_64_reg_e _index, uint8_t scale )
{
    return pack_pack(p_code_gen->p_offset, "%6i8%i8",
        0x62,
        0xF2,
        0x7D,
        0x48,
        0x92,
        0x04 | (_reg << 3) | _base,
        (_index << 3) | scale
    );
}

// AVX-512 Conversion Instructions
size_t x86_64_gen_vcvtdq2ps_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 )
{
    return pack_pack(p_code_gen->p_offset, "%5i8",
        0x62,
        0xF1,
        0x7C,
        0x48,
        0x5B | (_reg1 << 3) | _reg2
    );
}

// AVX-512 Mask Operations
size_t x86_64_gen_kmovb ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 )
{
    return pack_pack(p_code_gen->p_offset, "%4i8",
        0xC5,
        0xF9,
        0x90,
        0xC0 | (_reg1 << 3) | _reg2
    );
}

size_t x86_64_gen_kmovd ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 )
{
    return pack_pack(p_code_gen->p_offset, "%5i8",
        0x62,
        0xF1,
        0x7D,
        0x48,
        0x90 | (_reg1 << 3) | _reg2
    );
}

// AVX-512 Bit Manipulation
size_t x86_64_gen_vpternlogd_zmm_zmm_zmm_imm8 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3, uint8_t imm8 )
{
    return pack_pack(p_code_gen->p_offset, "%6i8%i8",
        0x62,
        0xF3,
        0x7D,
        0x48,
        0x25,
        0xC0 | (_reg1 << 3) | _reg2,
        imm8
    );
}

// AVX-512 Population Count
size_t x86_64_gen_vpopcntd_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 )
{
    return pack_pack(p_code_gen->p_offset, "%5i8",
        0x62,
        0xF2,
        0x7D,
        0x48,
        0x55 | (_reg1 << 3) | _reg2
    );
}

// AVX-512 Neural Network Instructions
size_t x86_64_gen_vpdpbusd_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 )
{
    return pack_pack(p_code_gen->p_offset, "%6i8",
        0x62,
        0xF2,
        0x7D,
        0x48,
        0x50,
        0xC0 | (_reg1 << 3) | _reg2
    );
}

// AVX-512 Compression Instructions
size_t x86_64_gen_vpcompressb_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 )
{
    return pack_pack(p_code_gen->p_offset, "%5i8",
        0x62,
        0xF2,
        0x7D,
        0x48,
        0x63 | (_reg1 << 3) | _reg2
    );
}

// AVX-512 Advanced Math Operations
size_t x86_64_gen_vexp2ps_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 )
{
    return pack_pack(p_code_gen->p_offset, "%5i8",
        0x62,
        0xF2,
        0x7D,
        0x48,
        0xC8 | (_reg1 << 3) | _reg2
    );
}

size_t x86_64_gen_vgetexppd_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 )
{
    return pack_pack(p_code_gen->p_offset, "%5i8",
        0x62,
        0xF2,
        0xFD,
        0x48,
        0x93 | (_reg1 << 3) | _reg2
    );
}

// AVX-512 FMA Operations
size_t x86_64_gen_vfmsub132ps_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 )
{
    return pack_pack(p_code_gen->p_offset, "%6i8",
        0x62,
        0xF2,
        0x7D,
        0x48,
        0x9A,
        0xC0 | (_reg1 << 3) | _reg2
    );
}

// AVX-512 Advanced Vector Operations
size_t x86_64_gen_vrangeps_zmm_zmm_zmm_imm8 ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3, uint8_t imm8 )
{
    return pack_pack(p_code_gen->p_offset, "%6i8%i8",
        0x62,
        0xF3,
        0x7D,
        0x48,
        0x50,
        0xC0 | (_reg1 << 3) | _reg2,
        imm8
    );
}

// AVX-512 Type Conversion Instructions
size_t x86_64_gen_vcvttpd2dq_ymm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 )
{
    return pack_pack(p_code_gen->p_offset, "%5i8",
        0x62,
        0xF1,
        0xFD,
        0x48,
        0x78 | (_reg1 << 3) | _reg2
    );
}

// AVX-512 Permute Instructions
size_t x86_64_gen_vpermt2ps_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 )
{
    return pack_pack(p_code_gen->p_offset, "%6i8",
        0x62,
        0xF2,
        0x7D,
        0x48,
        0x7F,
        0xC0 | (_reg1 << 3) | _reg2
    );
}

// AVX-512 Trigonometric Functions
size_t x86_64_gen_vsinps_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 )
{
    return pack_pack(p_code_gen->p_offset, "%5i8",
        0x62,
        0xF2,
        0x7D,
        0x48,
        0x51 | (_reg1 << 3) | _reg2
    );
}

size_t x86_64_gen_vcosps_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 )
{
    return pack_pack(p_code_gen->p_offset, "%5i8",
        0x62,
        0xF2,
        0x7D,
        0x48,
        0x52 | (_reg1 << 3) | _reg2
    );
}

// AVX-512 Conflict Detection Instructions
size_t x86_64_gen_vplzcntd_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2 )
{
    return pack_pack(p_code_gen->p_offset, "%5i8",
        0x62,
        0xF2,
        0x7D,
        0x48,
        0x44 | (_reg1 << 3) | _reg2
    );
}

// AVX-512 Neural Network Operations
size_t x86_64_gen_vpdpwssd_zmm_zmm_zmm ( x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, enum x86_64_reg_e _reg3 )
{
    return pack_pack(p_code_gen->p_offset, "%6i8",
        0x62,
        0xF2,
        0x7D,
        0x48,
        0x52,
        0xC0 | (_reg1 << 3) | _reg2
    );
}

// System Operations
size_t x86_64_gen_mfence ( x86_64_code_gen *p_code_gen )
{
    return pack_pack(p_code_gen->p_offset, "%3i8",
        0x0F,
        0xAE,
        0xF0
    );
}

size_t x86_64_gen_lfence ( x86_64_code_gen *p_code_gen )
{
    return pack_pack(p_code_gen->p_offset, "%3i8",
        0x0F,
        0xAE,
        0xE8
    );
}

size_t x86_64_gen_sfence ( x86_64_code_gen *p_code_gen )
{
    return pack_pack(p_code_gen->p_offset, "%3i8",
        0x0F,
        0xAE,
        0xF8
    );
}


// System
size_t x86_64_gen_cpuid(x86_64_code_gen *p_code_gen) {
    // The CPUID instruction is encoded as 0x0F 0xA2
    return pack_pack(p_code_gen->p_offset, "%2i8",
        0x0F,
        0xA2
    );
}

size_t x86_64_gen_rdtsc(x86_64_code_gen *p_code_gen) {
    // The RDTSC instruction is encoded as 0x0F 0x31
    return pack_pack(p_code_gen->p_offset, "%2i8",
        0x0F,
        0x31
    );
}

size_t x86_64_gen_pause(x86_64_code_gen *p_code_gen) {
    // The PAUSE instruction is encoded as 0xF3 0x90
    // (0x90 is NOP, but with the F3 prefix it becomes PAUSE)
    return pack_pack(p_code_gen->p_offset, "%2i8",
        0xF3,
        0x90
    );
}

// Basic arithmetic with immediates
size_t x86_64_gen_add_r64_imm32(x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, int32_t imm32)
{
    return pack_pack(p_code_gen->p_offset, "%3i8%i32",
        0x48,
        0x81,
        0xC0 | _reg,  // Add opcode extension (0) combined with register
        imm32
    );
}

size_t x86_64_gen_sub_r64_imm32(x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, int32_t imm32)
{
    return pack_pack(p_code_gen->p_offset, "%3i8%i32",
        0x48,
        0x81,
        0xE8 | _reg,  // Sub opcode extension (5) combined with register
        imm32
    );
}

size_t x86_64_gen_imul_r64_r64_imm32(x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2, int32_t imm32)
{
    return pack_pack(p_code_gen->p_offset, "%3i8%i32",
        0x48,
        0x69,
        0xC0 | (_reg1 << 3) | _reg2,
        imm32
    );
}

size_t x86_64_gen_cmp_r64_imm32(x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, int32_t imm32)
{
    return pack_pack(p_code_gen->p_offset, "%3i8%i32",
        0x48,
        0x81,
        0xF8 | _reg,  // CMP opcode extension (7) combined with register
        imm32
    );
}

size_t x86_64_gen_cmp_r64_r64(x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2)
{
    return pack_pack(p_code_gen->p_offset, "%3i8",
        0x48,
        0x39,
        0xC0 | (_reg2 << 3) | _reg1
    );
}

// Bit manipulation instructions
size_t x86_64_gen_bsf_r64_r64(x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2)
{
    return pack_pack(p_code_gen->p_offset, "%4i8",
        0x48,
        0x0F,
        0xBC,
        0xC0 | (_reg1 << 3) | _reg2
    );
}

size_t x86_64_gen_bsr_r64_r64(x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2)
{
    return pack_pack(p_code_gen->p_offset, "%4i8",
        0x48,
        0x0F,
        0xBD,
        0xC0 | (_reg1 << 3) | _reg2
    );
}

size_t x86_64_gen_bswap_r64(x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg)
{
    return pack_pack(p_code_gen->p_offset, "%2i8",
        0x48,
        0x0F,
        0xC8 | _reg
    );
}

size_t x86_64_gen_bt_r64_imm8(x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, uint8_t bit)
{
    return pack_pack(p_code_gen->p_offset, "%4i8%i8",
        0x48,
        0x0F,
        0xBA,
        0xE0 | _reg,
        bit
    );
}

size_t x86_64_gen_bts_r64_imm8(x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, uint8_t bit)
{
    return pack_pack(p_code_gen->p_offset, "%4i8%i8",
        0x48,
        0x0F,
        0xBA,
        0xE8 | _reg,
        bit
    );
}

// Bit counting instructions
size_t x86_64_gen_popcnt_r64(x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2)
{
    return pack_pack(p_code_gen->p_offset, "%4i8",
        0xF3,
        0x48,
        0x0F,
        0xB8,
        0xC0 | (_reg1 << 3) | _reg2
    );
}

size_t x86_64_gen_tzcnt_r64(x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2)
{
    return pack_pack(p_code_gen->p_offset, "%4i8",
        0xF3,
        0x48,
        0x0F,
        0xBC,
        0xC0 | (_reg1 << 3) | _reg2
    );
}

size_t x86_64_gen_lzcnt_r64(x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg1, enum x86_64_reg_e _reg2)
{
    return pack_pack(p_code_gen->p_offset, "%4i8",
        0xF3,
        0x48,
        0x0F,
        0xBD,
        0xC0 | (_reg1 << 3) | _reg2
    );
}

// Control flow implementations
size_t x86_64_gen_call_imm32(x86_64_code_gen *p_code_gen, int32_t imm32)
{
    return pack_pack(p_code_gen->p_offset, "%i8%i32",
        0xE8,
        imm32
    );
}

size_t x86_64_gen_call_indirect(x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, int32_t disp)
{
    return pack_pack(p_code_gen->p_offset, "%3i8%i32",
        0xFF,
        0x94,
        0x20 | (_reg << 3),
        disp
    );
}

// Conditional jump implementations
size_t x86_64_gen_je_rel32(x86_64_code_gen *p_code_gen, int rel32)
{
    return pack_pack(p_code_gen->p_offset, "%2i8%i32",
        0x0F,
        0x84,
        rel32
    );
}

size_t x86_64_gen_jne_rel32(x86_64_code_gen *p_code_gen, int rel32)
{
    return pack_pack(p_code_gen->p_offset, "%2i8%i32",
        0x0F,
        0x85,
        rel32
    );
}

size_t x86_64_gen_jg_rel32(x86_64_code_gen *p_code_gen, int rel32)
{
    return pack_pack(p_code_gen->p_offset, "%2i8%i32",
        0x0F,
        0x8F,
        rel32
    );
}

size_t x86_64_gen_jge_rel32(x86_64_code_gen *p_code_gen, int rel32)
{
    return pack_pack(p_code_gen->p_offset, "%2i8%i32",
        0x0F,
        0x8D,
        rel32
    );
}

size_t x86_64_gen_jl_rel32(x86_64_code_gen *p_code_gen, int rel32)
{
    return pack_pack(p_code_gen->p_offset, "%2i8%i32",
        0x0F,
        0x8C,
        rel32
    );
}

size_t x86_64_gen_jle_rel32(x86_64_code_gen *p_code_gen, int rel32)
{
    return pack_pack(p_code_gen->p_offset, "%2i8%i32",
        0x0F,
        0x8E,
        rel32
    );
}

// Stack operations
size_t x86_64_gen_push_imm32(x86_64_code_gen *p_code_gen, int32_t imm32)
{
    return pack_pack(p_code_gen->p_offset, "%i8%i32",
        0x68,  // PUSH imm32 opcode
        imm32
    );
}

size_t x86_64_gen_pushfq(x86_64_code_gen *p_code_gen)
{
    return pack_pack(p_code_gen->p_offset, "%i8",
        0x9C  // PUSHFQ opcode
    );
}

size_t x86_64_gen_popfq(x86_64_code_gen *p_code_gen)
{
    return pack_pack(p_code_gen->p_offset, "%i8",
        0x9D  // POPFQ opcode
    );
}

// Memory operations
size_t x86_64_gen_mov_reg_mem(x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, enum x86_64_reg_e base, int32_t disp)
{
    return pack_pack(p_code_gen->p_offset, "%3i8%i32",
        0x48,  // REX.W prefix
        0x8B,  // MOV r64, r/m64 opcode
        0x80 | (_reg << 3) | base,  // ModR/M byte
        disp
    );
}

size_t x86_64_gen_mov_mem_reg(x86_64_code_gen *p_code_gen, enum x86_64_reg_e base, int32_t disp, enum x86_64_reg_e _reg)
{
    return pack_pack(p_code_gen->p_offset, "%3i8%i32",
        0x48,  // REX.W prefix
        0x89,  // MOV r/m64, r64 opcode
        0x80 | (_reg << 3) | base,  // ModR/M byte
        disp
    );
}

size_t x86_64_gen_lea_r64_mem(x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, enum x86_64_reg_e base, enum x86_64_reg_e index, uint8_t scale, int32_t disp)
{
    return pack_pack(p_code_gen->p_offset, "%3i8%i8%i32",
        0x48,  // REX.W prefix
        0x8D,  // LEA opcode
        0x84 | (_reg << 3) | base,  // ModR/M byte
        (index << 3) | scale,  // SIB byte
        disp
    );
}

size_t x86_64_gen_mov_r32_m32(x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, enum x86_64_reg_e base, int32_t disp)
{
    return pack_pack(p_code_gen->p_offset, "%2i8%i32",
        0x8B,  // MOV r32, r/m32 opcode
        0x80 | (_reg << 3) | base,  // ModR/M byte
        disp
    );
}

size_t x86_64_gen_mov_m32_r32(x86_64_code_gen *p_code_gen, enum x86_64_reg_e base, int32_t disp, enum x86_64_reg_e _reg)
{
    return pack_pack(p_code_gen->p_offset, "%2i8%i32",
        0x89,  // MOV r/m32, r32 opcode
        0x80 | (_reg << 3) | base,  // ModR/M byte
        disp
    );
}

size_t x86_64_gen_movsx_r64_m8(x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, enum x86_64_reg_e base, int32_t disp)
{
    return pack_pack(p_code_gen->p_offset, "%4i8%i32",
        0x48,  // REX.W prefix
        0x0F,  // Two-byte opcode prefix
        0xBE,  // MOVSX r64, r/m8 opcode
        0x80 | (_reg << 3) | base,  // ModR/M byte
        disp
    );
}

size_t x86_64_gen_movsx_r64_m16(x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, enum x86_64_reg_e base, int32_t disp)
{
    return pack_pack(p_code_gen->p_offset, "%4i8%i32",
        0x48,  // REX.W prefix
        0x0F,  // Two-byte opcode prefix
        0xBF,  // MOVSX r64, r/m16 opcode
        0x80 | (_reg << 3) | base,  // ModR/M byte
        disp
    );
}

size_t x86_64_gen_movsx_r64_m32(x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, enum x86_64_reg_e base, int32_t disp)
{
    return pack_pack(p_code_gen->p_offset, "%2i8%i32",
        0x63,  // MOVSXD r64, r/m32 opcode
        0x80 | (_reg << 3) | base,  // ModR/M byte
        disp
    );
}

size_t x86_64_gen_movzx_r64_m8(x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, enum x86_64_reg_e base, int32_t disp)
{
    return pack_pack(p_code_gen->p_offset, "%4i8%i32",
        0x48,  // REX.W prefix
        0x0F,  // Two-byte opcode prefix
        0xB6,  // MOVZX r64, r/m8 opcode
        0x80 | (_reg << 3) | base,  // ModR/M byte
        disp
    );
}

size_t x86_64_gen_movzx_r64_m16(x86_64_code_gen *p_code_gen, enum x86_64_reg_e _reg, enum x86_64_reg_e base, int32_t disp)
{
    return pack_pack(p_code_gen->p_offset, "%4i8%i32",
        0x48,  // REX.W prefix
        0x0F,  // Two-byte opcode prefix
        0xB7,  // MOVZX r64, r/m16 opcode
        0x80 | (_reg << 3) | base,  // ModR/M byte
        disp
    );
}

// String operations
size_t x86_64_gen_movsb(x86_64_code_gen *p_code_gen) {
    return pack_pack(p_code_gen->p_offset, "%i8",
        0xA4  // MOVSB opcode
    );
}

size_t x86_64_gen_movsw(x86_64_code_gen *p_code_gen) {
    return pack_pack(p_code_gen->p_offset, "%2i8",
        0x66,  // Operand size override prefix
        0xA5   // MOVSW opcode
    );
}

size_t x86_64_gen_movsd(x86_64_code_gen *p_code_gen) {
    return pack_pack(p_code_gen->p_offset, "%i8",
        0xA5  // MOVSD opcode
    );
}

size_t x86_64_gen_movsq(x86_64_code_gen *p_code_gen) {
    return pack_pack(p_code_gen->p_offset, "%2i8",
        0x48,  // REX.W prefix
        0xA5   // MOVSQ opcode
    );
}

size_t x86_64_gen_rep_movsb(x86_64_code_gen *p_code_gen) {
    return pack_pack(p_code_gen->p_offset, "%2i8",
        0xF3,  // REP prefix
        0xA4   // MOVSB opcode
    );
}

size_t x86_64_gen_rep_movsw(x86_64_code_gen *p_code_gen) {
    return pack_pack(p_code_gen->p_offset, "%3i8",
        0xF3,  // REP prefix
        0x66,  // Operand size override prefix
        0xA5   // MOVSW opcode
    );
}

size_t x86_64_gen_rep_movsd(x86_64_code_gen *p_code_gen) {
    return pack_pack(p_code_gen->p_offset, "%2i8",
        0xF3,  // REP prefix
        0xA5   // MOVSD opcode
    );
}

// Atomic operations
size_t x86_64_gen_lock_xchg_m64_r64(x86_64_code_gen *p_code_gen, enum x86_64_reg_e base, int32_t disp, enum x86_64_reg_e reg) {
    return pack_pack(p_code_gen->p_offset, "%3i8%i32",
        0xF0,  // LOCK prefix
        0x48,  // REX.W prefix
        0x87,  // XCHG opcode
        0x80 | (reg << 3) | base,  // ModR/M byte
        disp
    );
}

size_t x86_64_gen_lock_cmpxchg_m64_r64(x86_64_code_gen *p_code_gen, enum x86_64_reg_e base, int32_t disp, enum x86_64_reg_e reg) {
    return pack_pack(p_code_gen->p_offset, "%4i8%i32",
        0xF0,  // LOCK prefix
        0x48,  // REX.W prefix
        0x0F,  // Two-byte opcode prefix
        0xB1,  // CMPXCHG opcode
        0x80 | (reg << 3) | base,  // ModR/M byte
        disp
    );
}

// AVX-512 vector instructions
size_t x86_64_gen_vaddpd_zmm_zmm_zmm(x86_64_code_gen *p_code_gen, enum x86_64_reg_e reg1, enum x86_64_reg_e reg2, enum x86_64_reg_e reg3) {
    return pack_pack(p_code_gen->p_offset, "%5i8",
        0x62,  // EVEX prefix
        0xF1,  // EVEX.RXB and EVEX.mm
        0xFD,  // EVEX.W and EVEX.vvvv
        0x48,  // EVEX.pp and EVEX.L'L
        0x58 | (reg1 << 3) | reg3,  // Opcode + ModR/M
        reg2 << 4  // EVEX.VVVV for second source operand
    );
}

size_t x86_64_gen_vandnpd_zmm_zmm_zmm(x86_64_code_gen *p_code_gen, enum x86_64_reg_e reg1, enum x86_64_reg_e reg2, enum x86_64_reg_e reg3) {
    return pack_pack(p_code_gen->p_offset, "%5i8",
        0x62,  // EVEX prefix
        0xF1,  // EVEX.RXB and EVEX.mm
        0xFD,  // EVEX.W and EVEX.vvvv
        0x48,  // EVEX.pp and EVEX.L'L
        0x55 | (reg1 << 3) | reg3,  // Opcode + ModR/M
        reg2 << 4  // EVEX.VVVV for second source operand
    );
}

size_t x86_64_gen_vandpd_zmm_zmm_zmm(x86_64_code_gen *p_code_gen, enum x86_64_reg_e reg1, enum x86_64_reg_e reg2, enum x86_64_reg_e reg3) {
    return pack_pack(p_code_gen->p_offset, "%5i8",
        0x62,  // EVEX prefix
        0xF1,  // EVEX.RXB and EVEX.mm
        0xFD,  // EVEX.W and EVEX.vvvv
        0x48,  // EVEX.pp and EVEX.L'L
        0x54 | (reg1 << 3) | reg3,  // Opcode + ModR/M
        reg2 << 4  // EVEX.VVVV for second source operand
    );
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
    
    /*
    ///////////////////////////
    // Assemble the function //
    ///////////////////////////
    {

        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
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
                p_code_gen->p_offset += x86_64_gen_and_r64_r64 (p_code_gen, (enum x86_64_reg_e) i, (enum x86_64_reg_e) j);
        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
        
        // or
        for (size_t i = 0; i < X86_64_REG_QUANTITY; i++)
            for (size_t j = 0; j < X86_64_REG_QUANTITY; j++)
                p_code_gen->p_offset += x86_64_gen_or_r64_r64 (p_code_gen, (enum x86_64_reg_e) i, (enum x86_64_reg_e) j);
        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
        
        // xor
        for (size_t i = 0; i < X86_64_REG_QUANTITY; i++)
            for (size_t j = 0; j < X86_64_REG_QUANTITY; j++)
                p_code_gen->p_offset += x86_64_gen_xor_r64_r64 (p_code_gen, (enum x86_64_reg_e) i, (enum x86_64_reg_e) j);
        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
        
        // test
        for (size_t i = 0; i < X86_64_REG_QUANTITY; i++)
            for (size_t j = 0; j < X86_64_REG_QUANTITY; j++)
                p_code_gen->p_offset += x86_64_gen_test_r64_r64 (p_code_gen, (enum x86_64_reg_e) i, (enum x86_64_reg_e) j);
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

        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
        
        // add
        for (size_t i = 0; i < X86_64_REG_QUANTITY; i++)
            for (size_t j = 0; j < X86_64_REG_QUANTITY; j++)
                p_code_gen->p_offset += x86_64_gen_add_r64_r64 (p_code_gen, (enum x86_64_reg_e) i, (enum x86_64_reg_e) j);
        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
        
        // sub
        for (size_t i = 0; i < X86_64_REG_QUANTITY; i++)
            for (size_t j = 0; j < X86_64_REG_QUANTITY; j++)
                p_code_gen->p_offset += x86_64_gen_sub_r64_r64 (p_code_gen, (enum x86_64_reg_e) i, (enum x86_64_reg_e) j);
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
                p_code_gen->p_offset += x86_64_gen_mov_r64_r64 (p_code_gen, (enum x86_64_reg_e) i, (enum x86_64_reg_e) j);
        p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
        
    }
    */

    // // Update page permissions 
    // if ( -1 == mprotect(p_code_gen->p_base, (size_t)sysconf(_SC_PAGESIZE), PROT_READ | PROT_EXEC) ) goto failed_to_update_permissions;

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

int x86_64_code_gen_node_construct ( x86_64_code_gen *p_code_gen, char *instruction, char *op1, char *op2, char *op3 ) 
{

    // Initialized data
    x86_64_op _op1, _op2, _op3;

    // Parse operand 1 
    if ( op1 )
    {
             if ( 0 == strncmp(op1, "RAX" , 3) ) _op1 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RAX };
        else if ( 0 == strncmp(op1, "RCX" , 3) ) _op1 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RCX };
        else if ( 0 == strncmp(op1, "RDX" , 3) ) _op1 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RDX };
        else if ( 0 == strncmp(op1, "RBX" , 3) ) _op1 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RBX };
        else if ( 0 == strncmp(op1, "RSP" , 3) ) _op1 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RSP };
        else if ( 0 == strncmp(op1, "RBP" , 3) ) _op1 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RBP };
        else if ( 0 == strncmp(op1, "RSI" , 3) ) _op1 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RSI };
        else if ( 0 == strncmp(op1, "RDI" , 3) ) _op1 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RDI };

        else if ( 0 == strncmp(op1, "XMM0", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM0 };
        else if ( 0 == strncmp(op1, "XMM1", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM1 };
        else if ( 0 == strncmp(op1, "XMM2", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM2 };
        else if ( 0 == strncmp(op1, "XMM3", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM3 };
        else if ( 0 == strncmp(op1, "XMM4", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM4 };
        else if ( 0 == strncmp(op1, "XMM5", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM5 };
        else if ( 0 == strncmp(op1, "XMM6", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM6 };
        else if ( 0 == strncmp(op1, "XMM7", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM7 };

        else if ( 0 == strncmp(op1, "YMM0", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM0 };
        else if ( 0 == strncmp(op1, "YMM1", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM1 };
        else if ( 0 == strncmp(op1, "YMM2", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM2 };
        else if ( 0 == strncmp(op1, "YMM3", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM3 };
        else if ( 0 == strncmp(op1, "YMM4", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM4 };
        else if ( 0 == strncmp(op1, "YMM5", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM5 };
        else if ( 0 == strncmp(op1, "YMM6", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM6 };
        else if ( 0 == strncmp(op1, "YMM7", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM7 };

        else if ( 0 == strncmp(op1, "ZMM0", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM0 };
        else if ( 0 == strncmp(op1, "ZMM1", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM1 };
        else if ( 0 == strncmp(op1, "ZMM2", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM2 };
        else if ( 0 == strncmp(op1, "ZMM3", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM3 };
        else if ( 0 == strncmp(op1, "ZMM4", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM4 };
        else if ( 0 == strncmp(op1, "ZMM5", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM5 };
        else if ( 0 == strncmp(op1, "ZMM6", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM6 };
        else if ( 0 == strncmp(op1, "ZMM7", 4) ) _op1 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM7 };

        else                                     _op1 = (x86_64_op) { ._type = X86_64_IMM64  , ._imm64 = atoi(op1) };
    }

    // Parse operand 2 
    if ( op2 )
    {
             if ( 0 == strncmp(op2, "RAX" , 3) ) _op2 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RAX };
        else if ( 0 == strncmp(op2, "RCX" , 3) ) _op2 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RCX };
        else if ( 0 == strncmp(op2, "RDX" , 3) ) _op2 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RDX };
        else if ( 0 == strncmp(op2, "RBX" , 3) ) _op2 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RBX };
        else if ( 0 == strncmp(op2, "RSP" , 3) ) _op2 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RSP };
        else if ( 0 == strncmp(op2, "RBP" , 3) ) _op2 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RBP };
        else if ( 0 == strncmp(op2, "RSI" , 3) ) _op2 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RSI };
        else if ( 0 == strncmp(op2, "RDI" , 3) ) _op2 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RDI };

        else if ( 0 == strncmp(op2, "XMM0", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM0 };
        else if ( 0 == strncmp(op2, "XMM1", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM1 };
        else if ( 0 == strncmp(op2, "XMM2", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM2 };
        else if ( 0 == strncmp(op2, "XMM3", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM3 };
        else if ( 0 == strncmp(op2, "XMM4", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM4 };
        else if ( 0 == strncmp(op2, "XMM5", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM5 };
        else if ( 0 == strncmp(op2, "XMM6", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM6 };
        else if ( 0 == strncmp(op2, "XMM7", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM7 };

        else if ( 0 == strncmp(op2, "YMM0", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM0 };
        else if ( 0 == strncmp(op2, "YMM1", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM1 };
        else if ( 0 == strncmp(op2, "YMM2", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM2 };
        else if ( 0 == strncmp(op2, "YMM3", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM3 };
        else if ( 0 == strncmp(op2, "YMM4", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM4 };
        else if ( 0 == strncmp(op2, "YMM5", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM5 };
        else if ( 0 == strncmp(op2, "YMM6", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM6 };
        else if ( 0 == strncmp(op2, "YMM7", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM7 };

        else if ( 0 == strncmp(op2, "ZMM0", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM0 };
        else if ( 0 == strncmp(op2, "ZMM1", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM1 };
        else if ( 0 == strncmp(op2, "ZMM2", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM2 };
        else if ( 0 == strncmp(op2, "ZMM3", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM3 };
        else if ( 0 == strncmp(op2, "ZMM4", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM4 };
        else if ( 0 == strncmp(op2, "ZMM5", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM5 };
        else if ( 0 == strncmp(op2, "ZMM6", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM6 };
        else if ( 0 == strncmp(op2, "ZMM7", 4) ) _op2 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM7 };

        else                                     _op2 = (x86_64_op) { ._type = X86_64_IMM64  , ._imm64 = atoi(op2) };

    }

    // Parse operand 3 
    if ( op3 )
    {
             if ( 0 == strncmp(op3, "RAX" , 3) ) _op3 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RAX };
        else if ( 0 == strncmp(op3, "RCX" , 3) ) _op3 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RCX };
        else if ( 0 == strncmp(op3, "RDX" , 3) ) _op3 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RDX };
        else if ( 0 == strncmp(op3, "RBX" , 3) ) _op3 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RBX };
        else if ( 0 == strncmp(op3, "RSP" , 3) ) _op3 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RSP };
        else if ( 0 == strncmp(op3, "RBP" , 3) ) _op3 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RBP };
        else if ( 0 == strncmp(op3, "RSI" , 3) ) _op3 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RSI };
        else if ( 0 == strncmp(op3, "RDI" , 3) ) _op3 = (x86_64_op) { ._type = X86_64_REG_64 , ._reg   = RDI };

        else if ( 0 == strncmp(op3, "XMM0", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM0 };
        else if ( 0 == strncmp(op3, "XMM1", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM1 };
        else if ( 0 == strncmp(op3, "XMM2", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM2 };
        else if ( 0 == strncmp(op3, "XMM3", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM3 };
        else if ( 0 == strncmp(op3, "XMM4", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM4 };
        else if ( 0 == strncmp(op3, "XMM5", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM5 };
        else if ( 0 == strncmp(op3, "XMM6", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM6 };
        else if ( 0 == strncmp(op3, "XMM7", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_128, ._reg   = XMM7 };

        else if ( 0 == strncmp(op3, "YMM0", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM0 };
        else if ( 0 == strncmp(op3, "YMM1", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM1 };
        else if ( 0 == strncmp(op3, "YMM2", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM2 };
        else if ( 0 == strncmp(op3, "YMM3", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM3 };
        else if ( 0 == strncmp(op3, "YMM4", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM4 };
        else if ( 0 == strncmp(op3, "YMM5", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM5 };
        else if ( 0 == strncmp(op3, "YMM6", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM6 };
        else if ( 0 == strncmp(op3, "YMM7", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_256, ._reg   = YMM7 };

        else if ( 0 == strncmp(op3, "ZMM0", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM0 };
        else if ( 0 == strncmp(op3, "ZMM1", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM1 };
        else if ( 0 == strncmp(op3, "ZMM2", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM2 };
        else if ( 0 == strncmp(op3, "ZMM3", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM3 };
        else if ( 0 == strncmp(op3, "ZMM4", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM4 };
        else if ( 0 == strncmp(op3, "ZMM5", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM5 };
        else if ( 0 == strncmp(op3, "ZMM6", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM6 };
        else if ( 0 == strncmp(op3, "ZMM7", 4) ) _op3 = (x86_64_op) { ._type = X86_64_REG_512, ._reg   = ZMM7 };

        else                                     _op3 = (x86_64_op) { ._type = X86_64_IMM64  , ._imm64 = atoi(op3) };
    }

    // No operands
    if ( !( op1 && op2 && op3 ) )
    {
             if ( 0 == strcmp(instruction, "RET")     ) p_code_gen->p_offset += x86_64_gen_ret(p_code_gen);
        else if ( 0 == strcmp(instruction, "NOP")     ) p_code_gen->p_offset += x86_64_gen_nop(p_code_gen);
        else if ( 0 == strcmp(instruction, "SYSCALL") ) p_code_gen->p_offset += x86_64_gen_syscall(p_code_gen);
    }

    // One operand
    if ( op1 && !( op2 && op3 ) )
    {
        if ( _op1._type == X86_64_REG_64 )
        {
                 if ( 0 == strcmp(instruction, "PUSH") ) p_code_gen->p_offset += x86_64_gen_push_reg(p_code_gen, _op1._reg);
            else if ( 0 == strcmp(instruction, "POP")  ) p_code_gen->p_offset += x86_64_gen_pop_reg(p_code_gen, _op1._reg);
            else if ( 0 == strcmp(instruction, "INC")  ) p_code_gen->p_offset += x86_64_gen_inc_reg(p_code_gen, _op1._reg);
            else if ( 0 == strcmp(instruction, "DEC")  ) p_code_gen->p_offset += x86_64_gen_dec_reg(p_code_gen, _op1._reg);
        } 
    }
    
    // Two operand
    if ( op1 && op2 && !op3 )
    {

        // reg, reg
        if ( _op1._type == X86_64_REG_64 && _op2._type == X86_64_REG_64 )
        {
                 if ( 0 == strcmp(instruction, "MOV")  ) p_code_gen->p_offset += x86_64_gen_mov_r64_r64(p_code_gen, _op1._reg, _op2._reg);
            else if ( 0 == strcmp(instruction, "AND")  ) p_code_gen->p_offset += x86_64_gen_and_r64_r64(p_code_gen, _op1._reg, _op2._reg);
            else if ( 0 == strcmp(instruction, "OR")   ) p_code_gen->p_offset += x86_64_gen_or_r64_r64(p_code_gen, _op1._reg, _op2._reg);
            else if ( 0 == strcmp(instruction, "XOR")  ) p_code_gen->p_offset += x86_64_gen_xor_r64_r64(p_code_gen, _op1._reg, _op2._reg);
            else if ( 0 == strcmp(instruction, "TEST") ) p_code_gen->p_offset += x86_64_gen_xor_r64_r64(p_code_gen, _op1._reg, _op2._reg);
            else if ( 0 == strcmp(instruction, "ADD")  ) p_code_gen->p_offset += x86_64_gen_add_r64_r64(p_code_gen, _op1._reg, _op2._reg);
            else if ( 0 == strcmp(instruction, "SUB")  ) p_code_gen->p_offset += x86_64_gen_sub_r64_r64(p_code_gen, _op1._reg, _op2._reg);
        } 

        // reg, imm64
        else if ( _op1._type == X86_64_REG_64 && _op2._type == X86_64_IMM64 )
        {
            if ( 0 == strcmp(instruction, "MOV") ) p_code_gen->p_offset += x86_64_gen_mov_reg_imm64(p_code_gen, _op1._reg, _op2._imm64);
        }

        else if ( _op1._type == X86_64_REG_128 && _op2._type == X86_64_REG_64 )
        {
            if ( 0 == strcmp(instruction, "VMOVDQA") ) p_code_gen->p_offset += x86_64_avx_gen_mov_reg128_reg64(p_code_gen, _op1._reg, _op2._reg);
        }
    }

    // Three operand
    if ( op1 && op2 && op3 )
    {

        // reg, reg, reg
        if ( _op1._type == X86_64_REG_128 && _op2._type == X86_64_REG_128 && _op3._type == X86_64_REG_128 )
        {
                 if ( 0 == strcmp(instruction, "VPADDD") ) p_code_gen->p_offset += x86_64_avx_gen_add_i32x4_reg128_reg128_reg128(p_code_gen, _op1._reg, _op2._reg, _op3._reg);
            else if ( 0 == strcmp(instruction, "VPADDQ") ) p_code_gen->p_offset += x86_64_avx_gen_add_i64x2_reg128_reg128_reg128(p_code_gen, _op1._reg, _op2._reg, _op3._reg);

            else if ( 0 == strcmp(instruction, "VADDPS") ) p_code_gen->p_offset += x86_64_avx_gen_add_f32x4_reg128_reg128_reg128(p_code_gen, _op1._reg, _op2._reg, _op3._reg);
            else if ( 0 == strcmp(instruction, "VSUBPS") ) p_code_gen->p_offset += x86_64_avx_gen_sub_f32x4_reg128_reg128_reg128(p_code_gen, _op1._reg, _op2._reg, _op3._reg);
            else if ( 0 == strcmp(instruction, "VMULPS") ) p_code_gen->p_offset += x86_64_avx_gen_mul_f32x4_reg128_reg128_reg128(p_code_gen, _op1._reg, _op2._reg, _op3._reg);
            else if ( 0 == strcmp(instruction, "VDIVPS") ) p_code_gen->p_offset += x86_64_avx_gen_div_f32x4_reg128_reg128_reg128(p_code_gen, _op1._reg, _op2._reg, _op3._reg);

            else if ( 0 == strcmp(instruction, "VADDPD") ) p_code_gen->p_offset += x86_64_avx_gen_add_f64x2_reg128_reg128_reg128(p_code_gen, _op1._reg, _op2._reg, _op3._reg);
        } 

        // reg, reg, reg
        if ( _op1._type == X86_64_REG_256 && _op2._type == X86_64_REG_256 && _op3._type == X86_64_REG_256 )
        {
                 if ( 0 == strcmp(instruction, "VADDPS") ) p_code_gen->p_offset += x86_64_avx_gen_add_f32x8_reg256_reg256_reg256(p_code_gen, _op1._reg, _op2._reg, _op3._reg);
        } 

    }

    // Success
    return 1;
}
