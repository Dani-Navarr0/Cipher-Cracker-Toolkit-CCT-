import os
import datetime
import re

# ANSI color codes for terminal output
from theme import RED, GREEN, YELLOW, BLUE, CYAN, GREY, WHITE, RESET, banner

def get_divisors(n):
    """Return all divisors of n."""
    divisors = []
    for i in range(1, int(n**0.5) + 1):
        if n % i == 0:
            divisors.append(i)
            if i != n // i:
                divisors.append(n // i)
    return sorted(divisors)

def create_matrix(string, rows, cols):
    """Create a matrix with the given dimensions from the string."""
    matrix = []
    for i in range(rows):
        start = i * cols
        end = start + cols
        matrix.append(string[start:end])
    return matrix

def read_matrix_columns(matrix, rows, cols):
    """Read matrix columns from left to right."""
    result = ""
    for j in range(cols):
        for i in range(rows):
            result += matrix[i][j]
    return result

def read_matrix_columns_reverse(matrix, rows, cols):
    """Read matrix columns from right to left."""
    result = ""
    for j in range(cols - 1, -1, -1):
        for i in range(rows):
            result += matrix[i][j]
    return result

def print_matrix(matrix, rows, cols):
    """Print the matrix to the console."""
    print(f"\n{BLUE}Matrix Representation:{RESET}")
    for row in matrix:
        print("  " + row)
    print()

def process_string(input_string, output_file="matrix_outputs.txt"):
    """Process the input string and save results to file."""
    length = len(input_string)
    divisors = get_divisors(length)
    
    print(f"\n{GREY}Input string:{RESET} {input_string}")
    print(f"{GREY}Length:{RESET} {length}")
    print(f"{GREY}Divisors:{RESET} {divisors}")
    
    try:
        with open(output_file, "w") as file:
            file.write(f"Input string: {input_string}\n")
            file.write(f"Length: {length}\n")
            file.write(f"Divisors: {divisors}\n\n")
            
            # Create and process all possible matrices
            for rows in divisors:
                cols = length // rows
                matrix = create_matrix(input_string, rows, cols)
                
                left_to_right = read_matrix_columns(matrix, rows, cols)
                right_to_left = read_matrix_columns_reverse(matrix, rows, cols)
                
                file.write(f"Matrix dimensions: {rows} rows x {cols} columns\n")
                file.write(f"Left to right reading: {left_to_right}\n")
                file.write(f"Right to left reading: {right_to_left}\n\n")
                
                print(f"{GREEN}Processed matrix:{RESET} {rows} rows x {cols} columns")
        
        print(f"\n{GREEN}All outputs saved to {output_file}{RESET}")
        return True
    except Exception as e:
        print(f"{RED}Error saving results to file: {e}{RESET}")
        return False

def run():
    banner("Matrix Generator", "Write a string into every n x m grid and read it back")
    
    input_mode = input(f"\n{GREY}Input mode ({RESET}{YELLOW}1 = Direct input{RESET}{GREY},{RESET} {YELLOW}2 = From file{RESET}{GREY}): {RESET}")
    
    if input_mode == '2':
        file_path = input(f"{GREY}Enter file path: {RESET}")
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                input_string = file.read().strip()
            print(f"{GREEN}File loaded successfully ({len(input_string)} characters).{RESET}")
        except Exception as e:
            print(f"{RED}Error reading file: {e}{RESET}")
            print(f"{YELLOW}Switching to direct input mode.{RESET}")
            input_string = input(f"{GREY}Enter your string: {RESET}")
    else:
        input_string = input(f"{GREY}Enter your string: {RESET}")
    
    if not input_string:
        print(f"{RED}Error: Empty input string.{RESET}")
        return
    
    # Ask for output file name
    output_file = input(f"{GREY}Enter output file name (default: matrix_outputs.txt): {RESET}")
    if not output_file.strip():
        output_file = "matrix_outputs.txt"
    
    # Ask if user wants to see a sample matrix
    show_sample = input(f"{GREY}Display a sample matrix? (y/n): {RESET}").lower()
    if show_sample == 'y':
        length = len(input_string)
        divisors = get_divisors(length)
        
        if len(divisors) > 2:
            # Choose a middle divisor for display
            sample_idx = len(divisors) // 2
            rows = divisors[sample_idx]
            cols = length // rows
            
            # Only display if matrix is small enough to be readable
            if rows <= 20 and cols <= 80:
                matrix = create_matrix(input_string, rows, cols)
                print_matrix(matrix, rows, cols)
                
                # Display sample readings
                left_to_right = read_matrix_columns(matrix, rows, cols)
                right_to_left = read_matrix_columns_reverse(matrix, rows, cols)
                
                print(f"{GREY}Sample left to right reading:{RESET}")
                print(f"{left_to_right}\n")
                
                print(f"{GREY}Sample right to left reading:{RESET}")
                print(f"{right_to_left}\n")
            else:
                print(f"{YELLOW}Sample matrix too large to display ({rows}x{cols}).{RESET}")
    
    # Process the string
    process_string(input_string, output_file)
    
    # Ask if user wants to analyze specific dimensions
    analyze_specific = input(f"\n{GREY}Analyze a specific matrix dimension? (y/n): {RESET}").lower()
    if analyze_specific == 'y':
        length = len(input_string)
        divisors = get_divisors(length)
        
        print(f"{YELLOW}Available dimensions (rows x columns):{RESET}")
        for i, rows in enumerate(divisors):
            cols = length // rows
            print(f"{i+1}: {rows} rows x {cols} columns")
        
        try:
            choice = int(input(f"{GREY}Enter dimension number: {RESET}"))
            if 1 <= choice <= len(divisors):
                rows = divisors[choice-1]
                cols = length // rows
                matrix = create_matrix(input_string, rows, cols)
                
                if rows <= 20 and cols <= 80:
                    print_matrix(matrix, rows, cols)
                else:
                    print(f"{YELLOW}Matrix too large to display ({rows}x{cols}).{RESET}")
                
                left_to_right = read_matrix_columns(matrix, rows, cols)
                right_to_left = read_matrix_columns_reverse(matrix, rows, cols)
                
                print(f"{GREY}Left to right reading:{RESET}")
                print(f"{left_to_right}\n")
                
                print(f"{GREY}Right to left reading:{RESET}")
                print(f"{right_to_left}\n")
            else:
                print(f"{RED}Invalid choice.{RESET}")
        except ValueError:
            print(f"{RED}Invalid input.{RESET}")
    
    print(f"\n{RED}===================================={RESET}")

if __name__ == "__main__":
    run()