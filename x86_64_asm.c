/** !
 * g assembler (x86)
 *
 * @file gasm.c
 * 
 * @author Jacob Smith
 */

// Standard library
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>

// code gen module


/** !
 * Evaluate an assembly instruction
 * 
 * @param p_input  TODO
 * @param p_output TODO  
 * 
 * @return 1 on success, 0 on error
 */
int gasm_eval ( const char *p_input, char *p_output )
{

    // Initialized data
    char *p_token = strtok(p_input, " ");
    char  _token[1024] = { 0 };

    // Tokenize the string
    while ( p_token != NULL )
    {

        memcpy(_token, p_token, 1024);

        // Initialized data
        size_t len = strlen(p_token) - 1;

        _token[len] = '\0';

        if (_token[len - 1] == ':') {
            _token[len - 1] = '\0',
            sprintf(p_output, "Label: \"%s\"\n", _token);
            goto done;
        }

        switch (_token[0])
        {
        case '!':
            sprintf(p_output, "Directive\n");
            goto done;
        
        default:

            // Walk the string        
            for (size_t i = 0; i < len; i++)

                // Transform the string to upper case
                _token[i] = toupper(p_token[i]);
            
            goto done;
        }
        done:
        

        // Tokenize
        p_token = strtok(NULL, " ,");
    }
    
    // Success
    return 1;
}

// Entry point
int main ( int argc, const char *argv[] )
{

    // Initialized data
    char _in_buf[1024] = { 0 };
    char _out_buf[1024] = { 0 };


    // REPL
    while ( !feof(stdin) )
    {

        // Wipe the tokens
        memset(_in_buf, 0, 1024),
        memset(_out_buf, 0, 1024);

        // Read a line from standard in
        fgets(_in_buf,1024,stdin);

        // Evaluate
        gasm_eval(_in_buf, 0);

        // Write a line to standard out
        fprintf(stdout, _out_buf);
        
    }
    

    // Success
    return EXIT_SUCCESS;

    // Error handling
    {
        //
    }
}

void gasm_init ( void )
{

    // TODO
    //

    // Done
    return;
}
