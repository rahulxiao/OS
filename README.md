# 🐚 Shell Scripting Mastery Collection

A comprehensive collection of **shell scripting examples** covering essential programming concepts with detailed explanations and practical implementations.

## 📋 Table of Contents

- [Overview](#overview)
- [Topics Covered](#topics-covered)
- [Quick Start](#quick-start)
- [Examples by Category](#examples-by-category)
  - [Arrays](#arrays)
  - [File Parsing](#file-parsing)
  - [If-Else Statements](#if-else-statements)
  - [Loops with Continue](#loops-with-continue)
  - [Loops with Break](#loops-with-break)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## 🎯 Overview

This repository contains **25+ practical shell scripting examples** designed to help you master fundamental programming concepts in bash. Each example includes:

- ✅ **Complete working code**
- 📝 **Detailed explanations**
- 🔍 **Real-world use cases**
- 🚀 **Best practices**

Perfect for beginners learning shell scripting or experienced developers looking for quick reference examples.

## 📚 Topics Covered

| Category | Examples | Key Concepts |
|----------|----------|--------------|
| **Arrays** | 5 examples | Array creation, manipulation, iteration, finding max/min |
| **File Parsing** | 6 examples | CSV processing, data filtering, format conversion |
| **If-Else** | 5 examples | Conditional logic, numeric comparisons, file checks |
| **Continue Loops** | 5 examples | Skip iterations, filter data, handle exceptions |
| **Break Loops** | 5 examples | Early termination, search operations, user input |

## 🚀 Quick Start

1. **Clone or download** this repository
2. **Navigate** to the project directory
3. **Make scripts executable**:
   ```bash
   chmod +x *.sh
   ```
4. **Run examples**:
   ```bash
   ./array_examples.sh
   ./file_parsing.sh
   ```

## 📖 Examples by Category

### 🔢 Arrays

**Create and manipulate arrays with ease**

```bash
# Create and print array elements
arr=(10 20 30 40 50)
echo "All elements: ${arr[@]}"
echo "Total count: ${#arr[@]}"
```

**Key Features:**
- Array initialization and access
- Dynamic array building from user input
- Mathematical operations (sum, max, min)
- Reverse iteration techniques

### 📄 File Parsing

**Process CSV files and structured data**

```bash
# Search CSV by ID
while IFS=',' read -r cid name age; do
    if [[ "$cid" == "$id" ]]; then
        printf "%s,%s\n" "$name" "$age"
        found=1
        break
    fi
done < <(tail -n +2 users.csv)
```

**Key Features:**
- CSV data processing
- Field extraction and filtering
- Format conversion (CSV to TSV)
- Safe file reading with error handling

### 🔀 If-Else Statements

**Master conditional logic**

```bash
# Even or odd check
if (( n%2==0 )); then 
    echo Even
else 
    echo Odd
fi
```

**Key Features:**
- Numeric comparisons
- File existence checks
- String validation
- Complex conditional chains

### ⏭️ Loops with Continue

**Skip iterations intelligently**

```bash
# Skip zeros in array
for n in "${arr[@]}"; do
    (( n==0 )) && continue
    echo "$n"
done
```

**Key Features:**
- Skip unwanted elements
- Filter comments and empty lines
- Handle exceptions gracefully
- Process selective data

### ⏹️ Loops with Break

**Terminate loops early when needed**

```bash
# Stop on first negative number
for n in "${arr[@]}"; do
    if (( n<0 )); then
        echo "Found negative: stopping"
        break
    fi
    echo $n
done
```

**Key Features:**
- Early loop termination
- Search and stop operations
- User input handling
- Controlled iteration limits

## 💡 Usage

### Running Individual Examples

Each example is self-contained and can be run independently:

```bash
# Array examples
bash -c 'arr=(10 20 30); echo "Sum: $((${arr[0]} + ${arr[1]} + ${arr[2]}))"'

# File parsing
echo "ID,Name,Age" > test.csv
echo "1,Alice,23" >> test.csv
bash -c 'while IFS=, read -r id name age; do echo "Name: $name"; done < test.csv'
```

### Interactive Examples

Many examples include user input prompts:

```bash
# Interactive number checker
read -p "Enter a number: " n
if (( n%2==0 )); then echo "Even"; else echo "Odd"; fi
```

## 🛠️ Requirements

- **Bash shell** (version 4.0 or higher)
- **Unix-like environment** (Linux, macOS, WSL)
- **Basic terminal knowledge**

## 📝 Best Practices Demonstrated

- ✅ **Error handling** with `set -euo pipefail`
- ✅ **Safe variable handling** with proper quoting
- ✅ **Input validation** and sanitization
- ✅ **Efficient file processing** techniques
- ✅ **Clean, readable code** structure

## 🤝 Contributing

Contributions are welcome! Please feel free to:

1. **Fork** the repository
2. **Create** a feature branch
3. **Add** new examples or improve existing ones
4. **Submit** a pull request

### Guidelines for Contributions

- Include clear explanations for new examples
- Follow the existing code style
- Test examples thoroughly
- Update documentation as needed

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🎓 Learning Path

**For Beginners:**
1. Start with **Arrays** → **If-Else** → **Basic Loops**
2. Practice with **File Parsing** examples
3. Master **Continue** and **Break** techniques

**For Intermediate Users:**
1. Combine multiple concepts in custom scripts
2. Adapt examples for your specific use cases
3. Explore advanced bash features

## 📞 Support

If you find these examples helpful or have questions:

- ⭐ **Star** this repository
- 🐛 **Report** issues or bugs
- 💬 **Ask** questions in discussions
- 📧 **Share** your own examples

---

**Happy Scripting! 🐚✨**

> *Master the command line, one script at a time.*