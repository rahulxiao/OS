// Q&A Data Structure
const qaData = {
    coding: [
        {
            question: "Array in Shell Script",
            answer: "```bash\n#!/bin/bash\nnums=()\nfor i in {1..5};\ndo\n    read -p \"Enter number $i: \" n\n    nums+=(\"$n\")\ndone\n\necho \"All numbers: ${nums[@]}\"\necho \"Second number: ${nums[1]}\"\n```\n\nExplanation:\n- nums=() initializes an empty array.\n- nums+=(\"$n\") adds input to array.\n- ${nums[@]} prints all elements.\n- ${nums[1]} prints the second element."
        },
        {
            question: "File Parsing (CSV search by ID)",
            answer: "```bash\n#!/bin/bash\nread -p \"Enter ID to search: \" search_id\nwhile IFS=',' read -r id name age; do\n    if [[ $id == \"$search_id\" ]]; then\n        echo \"Name: $name, Age: $age\"\n        break\n    fi\ndone < <(tail -n +2 users.csv)\n```\n\nExplanation:\n- IFS=',' splits CSV by comma.\n- tail -n +2 skips header.\n- Prints the first matching record and stops."
        },
        {
            question: "If-Else Statement (Even or Odd)",
            answer: "```bash\n#!/bin/bash\nread -p \"Enter a number: \" num\nif (( num % 2 == 0 )); then\n    echo \"$num is Even\"\nelse\n    echo \"$num is Odd\"\nfi\n```\n\nExplanation:\n- % 2 checks divisibility.\n- Uses if-else to select the output."
        },
        {
            question: "Loop with Continue (skip zero)",
            answer: "```bash\n#!/bin/bash\nnumbers=(5 0 3 7)\nfor n in \"${numbers[@]}\"; do\n    if (( n == 0 )); then\n        continue\n    fi\n    echo \"Number: $n\"\ndone\n```\n\nExplanation:\n- continue skips the iteration for zero.\n- Only non-zero numbers are printed."
        },
        {
            question: "Loop with Break (stop on negative)",
            answer: "```bash\n#!/bin/bash\nnumbers=(5 3 -2 8)\nfor n in \"${numbers[@]}\"; do\n    if (( n < 0 )); then\n        echo \"Negative number found, stopping loop.\"\n        break\n    fi\n    echo \"Number: $n\"\ndone\n```\n\nExplanation:\n- break exits loop immediately on negative.\n- Earlier positive numbers are printed."
        }
    ],
    domain: [
        {
            question: "Define Domain of Protection.",
            answer: "A domain is a set of objects along with the access rights a process has for them. It defines what a process can access and how (read, write, execute).\n\nExplanation:\nThink of a domain as a \"workspace\" for a process. Only the objects in its domain are visible, and only the allowed operations can be performed.\n\nExample: A process may have read/write access to file F1 but read-only access to file F2. This prevents unauthorized modifications."
        },
        {
            question: "Define Access Matrix.",
            answer: "An Access Matrix is a table representing all subjects (processes/users), objects (files/resources), and the access rights each subject has.\n\nExplanation:\nRows: Each subject (process or user)\nColumns: Each object (file, device, resource)\nCells: The allowed operations (read, write, execute)\nPurpose: Shows all access rights in the system, not just one process.\n\nExample: If process P1 has read/write to file F1, the table cell at (P1, F1) contains R,W."
        },
        {
            question: "Difference between Domain and Access Matrix:",
            answer: "Feature | Domain | Access Matrix\nScope | Single process | All processes in the system\nPurpose | Defines access rights for a process | Shows all rights of all processes\nForm | Set of (object, rights) pairs | Table of subjects × objects\n\nExplanation:\nDomain: Think of it as the \"personal access list\" for a single process.\nAccess Matrix: Think of it as the \"master chart\" of the system, showing who can do what for all processes and resources."
			},
			{
			question: "Explain the Access Matrix with example table",
			answer: "An Access Matrix is a protection model in operating systems that describes the rights of each domain (subject) over each object (resource).\n\nRows → Domains (processes/subjects).\nColumns → Objects (files, devices, etc.).\nCell[i, j] → The set of rights that domain i has over object j.\n\nDomain | File1 | File2 | Printer\nD1 | Read | Read/Write | —\nD2 | — | Read | Print\n\nInterpretation of the given table:\n- D1 can read File1, and read/write File2. It has no access to the printer.\n- D2 can read File2 and print using the printer. It has no access to File1.\n\nConclusion:\nThe Access Matrix provides a formal representation of protection in a system. It ensures controlled access to resources by clearly specifying what operations each domain is allowed to perform on each object."
			},
			{
			question: "Explain the Modified Access Matrix and domain rights",
			answer: "A Modified Access Matrix is an extension of the access matrix model in operating systems where domains are also treated as objects. This allows representation of domain switching rights in addition to normal operations on files and devices.\n\nRows → Domains (subjects)\nColumns → Objects (files, printer, etc.) + Domains\nCell[i, j] → Rights of domain i over object/domain j\n\nDomain | F1 | F2 | F3 | Printer | D1 | D2 | D3 | D4\nD1 | read | — | read | — | — | switch | — | —\nD2 | — | — | — | print | — | — | switch | switch control\nD3 | — | read | execute | — | — | — | — | —\nD4 | write | — | write | — | switch | — | — | —\n\nInterpretation of the table:\n- D1 can read F1, read F3, and switch to D2.\n- D2 can print on the printer, switch to D3, and has switch control over D4.\n- D3 can read F2 and execute F3.\n- D4 can write to F1, write to F3, and switch to D1.\n\nConclusion:\nThis Modified Access Matrix shows how processes in different domains have specific access rights to objects, and how domain switching gives flexibility by letting a process move into another domain with different rights."
			}
    ],
    mutex: [
        {
            question: "What is a Mutex Lock?",
            answer: "A mutex (mutual exclusion) lock allows only one process to enter the critical section at a time.\n\nExplanation:\nThe critical section is a part of code accessing shared resources.\nMutex ensures no two processes modify the same resource simultaneously, preventing race conditions.\n\nExample: Two threads cannot print to the same printer at the same time; only one thread can hold the mutex lock."
        },
        {
            question: "What is a Semaphore?",
            answer: "A semaphore is a synchronization tool used to control access to resources. It can be:\n\nBinary Semaphore: Works like a mutex (0 or 1)\nCounting Semaphore: Allows multiple processes to access limited resources\n\nOperations:\nwait() or P() → Decreases the semaphore (request resource)\nsignal() or V() → Increases the semaphore (release resource)\n\nExplanation:\nSemaphores can be used for mutual exclusion or to coordinate processes.\n\nExample: Limiting access to 3 printers with a counting semaphore of value 3; only 3 threads can use printers simultaneously."
        },
        {
            question: "Difference between Mutex and Semaphore:",
            answer: "Feature | Mutex | Semaphore\nType | Binary (0 or 1) | Binary or Counting\nUse | Mutual exclusion only | Mutual exclusion + process coordination\nOwnership | Only the locking thread can unlock | Any process can signal\n\nExplanation:\nMutex is simpler: only one thread can enter critical section, and must release its own lock.\nSemaphore is more flexible: multiple threads can share resources, and any process can signal, making it useful for synchronization."
        }
    ],
    critical: [
        {
            question: "What is the Critical-Section Problem?",
            answer: "Ensuring safe access to shared resources by multiple processes.\n\nRequirements:\nMutual Exclusion – Only one process can enter the critical section at a time.\nProgress – If no process is in the critical section, a requesting process must enter without unnecessary delay.\nBounded Waiting – No process waits indefinitely; each process gets a turn.\n\nExplanation:\nThe problem arises when multiple processes try to access shared resources like files, printers, or memory.\nSolving it avoids race conditions and ensures data consistency."
        },
        {
            question: "What is Peterson's Solution?",
            answer: "A software algorithm for two processes using a flag array and turn variable.\n\nExplanation:\nEnsures mutual exclusion and no starvation.\nEach process indicates its intent to enter the critical section using a flag and waits if it is the other process's turn.\nSimple but limited to two processes in this classic version."
		},
		{
			question: "What is a Race Condition?",
			answer: "A race condition is an undesirable situation that occurs when two or more processes (or devices) try to perform operations at the same time on a shared resource, but the correctness depends on the order of execution. If the proper sequence is not maintained, the result becomes inconsistent or incorrect."
		},
		{
			question: "What is the Critical Section Problem? (Definition)",
			answer: "In a system with multiple processes {p0, p1, …, pn-1}, each process has a critical section, where it accesses or modifies shared resources (variables, tables, files, etc.). The Critical Section Problem is to design a protocol that ensures: When one process is executing in its critical section, no other process can execute in its critical section. Each process must request permission before entering (entry section), and after leaving (exit section), it continues in its remainder section."
		},
		{
			question: "Three Requirements of a Correct Critical-Section Solution",
			answer: "Mutual Exclusion: If one process Pi is in the critical section, no other process may enter its critical section.\n\nProgress: If no process is in the critical section and there are processes that want to enter, one of them must be allowed to proceed. The decision cannot be postponed indefinitely.\n\nBounded Waiting: There must be a limit on how many times other processes can enter their critical section after a process has made a request and before that request is granted.\n\n(Assume each process runs at nonzero speed, with no assumption about relative speeds.)"
		},
		{
			question: "Explain Peterson’s Solution for Two Processes",
			answer: "Peterson’s Solution provides software synchronization for two processes. It assumes atomic load and store operations.\n\nShared variables:\nint turn;         // whose turn to enter critical section\nboolean flag[2];  // flag[i] = true if process Pi wants to enter\n\nWorking principle:\n1) Each process sets its flag to true (wants to enter).\n2) It then gives the turn to the other process.\n3) A process enters the critical section only if either the other process is not interested (flag[j] = false), or it’s this process’s turn.\n\nLimitations:\nAlgorithmically correct, but not guaranteed on modern multiprocessor architectures due to compiler/hardware instruction reordering. Still important conceptually to demonstrate solving the critical section problem."
		}
    ],
    security: [
        {
			question: "Explain Four-Layered Security with examples, problems, and solutions.",
			answer: "Four-Layered Security is a defense-in-depth strategy. It protects computer systems by applying multiple levels of security. If one layer fails, the others continue to defend the system.\n\n1. Physical Layer – Protects the actual hardware\nExample: locks, CCTV cameras, biometric access, restricted entry.\nProblem: Unauthorized persons may steal or damage equipment.\nSolution: Use surveillance, physical barriers, and restricted access areas.\n\n2. Network Layer – Protects data in transit\nExample: firewalls, VPNs, Intrusion Detection/Prevention Systems (IDS/IPS).\nProblem: Hackers can intercept or modify data during transmission.\nSolution: Encrypt communication, configure firewalls, monitor with IDS/IPS.\n\n3. Operating System Layer – Manages authentication and access control\nExample: user accounts, passwords, access control lists (ACLs).\nProblem: Attackers may gain unauthorized access or escalate privileges.\nSolution: Strong authentication (multi-factor login, biometrics), apply least-privilege rules, patch OS vulnerabilities.\n\n4. Application Layer – Protects programs and software\nExample: secure coding, antivirus software, timely patches.\nProblem: Applications can be exploited (SQL injection, malware, buffer overflow).\nSolution: Regular updates, input validation, use security tools (antivirus, firewalls).\n\nConclusion:\nLayered security creates a multi-level defense system. Even if one layer is breached, other layers continue protecting, ensuring overall system safety."
        }
    ],
    program: [
        {
            question: "What are Program Threats?",
            answer: "Malicious software or code exploiting vulnerabilities.\n\nExamples:\nTrojan Horse: Appears useful but harms system.\nTrap Door (Backdoor): Hidden entry bypassing security.\nLogic Bomb: Executes when a condition is met.\nBuffer/Stack Overflow: Exploits memory overflow to inject code.\nVirus/Worm: Self-replicating code that spreads and damages files.\n\nExplanation:\nProgram threats can compromise confidentiality, integrity, or availability of data."
        }
    ],
    classification: [
        {
            question: "Classify security problems.",
            answer: "Confidentiality: Prevent unauthorized access.\nIntegrity: Prevent unauthorized modification.\nAvailability: Ensure resources/services are accessible.\n\nExplanation:\nThese three are the core goals of information security.\nExample: Protecting a bank database ensures all three (data is secret, accurate, and always available)."
        }
	],
	memory: [
		{
			question: "Role of Base and Limit Registers in Memory Protection",
			answer: "Base register: Holds starting physical address of a process.\nLimit register: Holds the size of the process.\nProtection: Access outside [base, base + limit] triggers trap.\nExample: Base = 1000, Limit = 300 → valid addresses = 1000 to 1299"
		},
		{
			question: "Difference Between Logical and Physical Address",
			answer: "Logical Address | Physical Address\nGenerated by CPU | Actual address in memory\nPart of logical address space | Part of physical address space\nUsed in program instructions | Used by memory hardware"
		},
		{
			question: "Stages of Address Binding",
			answer: "1. Compile-time: Absolute addresses known.\n2. Load-time: Relocatable code; addresses fixed at load.\n3. Execution-time: Dynamic binding during execution."
		},
		{
			question: "Dynamic Loading",
			answer: "Definition: Load routine only when called.\nAdvantages: Saves memory, faster program execution."
		},
		{
			question: "Internal vs External Fragmentation",
			answer: "Internal: Wasted memory inside allocated block. Example: Process needs 27 KB, allocated 32 KB → 5 KB wasted.\nExternal: Free memory split into small unusable blocks. Example: Free blocks = 10 KB + 15 KB; process needs 20 KB → cannot fit."
		},
		{
			question: "Compaction",
			answer: "Rearranging memory to combine free blocks and reduce external fragmentation.\nPossible in relocatable memory systems."
		},
		{
			question: "Page and Frame",
			answer: "Page: Fixed-size block of logical memory.\nFrame: Fixed-size block in physical memory."
		},
		{
			question: "Virtual Memory (2 Advantages)",
			answer: "Allows execution of processes larger than physical memory.\nProvides isolation and protection between processes."
		},
		{
			question: "Demand Paging",
			answer: "Load pages into memory only when required by the process.\nReduces memory usage and I/O overhead."
		},
		{
			question: "Hardware Address Protection",
			answer: "CPU generates logical address → Base + Logical Address = Physical Address\nCheck: Logical Address < Limit? → Yes: Access allowed | No: Trap"
		},
		{
			question: "Compile-time vs Load-time vs Execution-time Binding",
			answer: "Feature | Compile-time | Load-time | Execution-time\nAddress known? | Yes | No | No\nCode relocatable? | No | Yes | Yes\nFlexibility | Low | Medium | High\nExample | Absolute code | Program loaded anywhere | Paging/Segmentation"
		},
		{
			question: "Logical vs Physical Address Space (Diagram)",
			answer: "Logical Address Space       Physical Memory\n[0 .. n-1]                [Base .. Base+Limit-1]\nCPU generates LA → MMU → PA"
		},
		{
			question: "Swapping: Advantages & Disadvantages",
			answer: "Advantages: Multi-programming, frees memory.\nDisadvantages: High overhead due to disk I/O, execution delayed."
		},
		{
			question: "Fragmentation & Reduction",
			answer: "Problem: Wasted memory reduces efficiency.\nReduce External Fragmentation: Compaction, Paging, Segmentation."
		},
		{
			question: "Paging Mechanism (Diagram)",
			answer: "Logical Address → Page Number + Offset\nPage Table: Page # → Frame #\nPhysical Address = Frame # * Frame Size + Offset"
		},
		{
			question: "Steps of Address Translation in Paging",
			answer: "1. CPU generates logical address (page#, offset).\n2. MMU looks up page table → frame number.\n3. Physical address = frame# * frame_size + offset."
		},
		{
			question: "Logical vs Physical Memory",
			answer: "Virtual Memory | Physical Memory\nLarger than RAM | Actual RAM\nCan execute partial pages | Must be fully in RAM\nManaged by OS | Managed by hardware"
		},
		{
			question: "Address Binding at Different Stages",
			answer: "Compile-time: Absolute addresses known; code not relocatable.\nLoad-time: Relocatable code; addresses fixed at load.\nExecution-time: Dynamic relocation; used in paging."
		},
		{
			question: "Swapping in Detail",
			answer: "Temporarily move inactive processes to disk.\nIssues: Context-switch time, pending I/O problem, modified swapping."
		},
		{
			question: "Internal vs External Fragmentation + 50% Rule",
			answer: "Internal: Wasted memory inside allocated block.\nExternal: Free blocks unusable.\n50% Rule: External fragmentation ≈ 50% of allocated memory (Knuth)."
		},
		{
			question: "Paging in Detail",
			answer: "Page Table Structure: Page # → Frame #\nAddress Translation: LA → (Page#, Offset) → Frame# → PA\nExample: Page size = 1 KB, LA = 2048 → Page# = 2, Offset = 0, Frame# = 5 → PA = 5120"
		},
		{
			question: "Virtual Memory in Detail",
			answer: "Virtual Address Space: Logical memory view of process.\nBenefits: Efficient memory use, isolation.\nDemand Paging: Load pages only when needed.\nDemand Segmentation: Load segments on demand."
		},
		{
			question: "Numerical: Logical → Physical Address",
			answer: "1. Divide logical address into page # and offset.\n2. Lookup page # in page table → frame #.\n3. PA = frame# * frame_size + offset."
		},
		{
			question: "Comparison: Swapping vs Paging; Fragmentation vs Compaction",
			answer: "Feature | Swapping | Paging\nMemory use | Entire process swapped | Only required pages\nFragmentation | External | Minimal\nOverhead | High | Moderate\n\nFeature | Fragmentation | Compaction\nProblem | Wasted memory | Rearranging memory\nSolution | Paging/Segmentation | Combine free blocks"
		}
	],
	shell: [
			{
				question: "Shell Coding",
				answer: "Shell is a command-line interpreter that allows users to interact with the operating system. It is a program that takes commands from the user and executes them."
			},
			{
				question: "Array in Shell Script",
				answer: "Write a shell script to accept 5 numbers from the user, store them in an array, and print all the numbers along with the second number.\n\n```bash\n#!/bin/bash\nnums=()\nfor i in {1..5};\ndo\n    read -p \"Enter number $i: \" n\n    nums+=(\"$n\")\ndone\n\n echo \"All numbers: ${nums[@]}\"\n echo \"Second number: ${nums[1]}\"\n```\n\nExplanation:\n- nums=() initializes an empty array.\n- nums+=(\"$n\") adds input to array.\n- ${nums[@]} prints all elements.\n- ${nums[1]} prints the second element."
			},
			{
				question: "File Parsing (CSV search by ID)",
				answer: "Given a CSV file users.csv with columns ID,Name,Age, write a shell script to search for a user by ID and display their name and age.\n\n```bash\n#!/bin/bash\nread -p \"Enter ID to search: \" search_id\nwhile IFS=',' read -r id name age; do\n    if [[ $id == \"$search_id\" ]]; then\n        echo \"Name: $name, Age: $age\"\n        break\n    fi\ndone < <(tail -n +2 users.csv)\n```\n\nExplanation:\n- IFS=',' splits CSV by comma.\n- tail -n +2 skips header.\n- Compares each line’s ID with input and prints matching record; breaks after first match."
			},
			{
				question: "If-Else Statement (Even or Odd)",
				answer: "Write a shell script to check if a given number is even or odd.\n\n```bash\n#!/bin/bash\nread -p \"Enter a number: \" num\nif (( num % 2 == 0 )); then\n    echo \"$num is Even\"\nelse\n    echo \"$num is Odd\"\nfi\n```\n\nExplanation:\n- % 2 checks divisibility.\n- Executes different commands based on condition."
			},
			{
				question: "Loop with Continue (skip zero)",
				answer: "Write a shell script that loops through an array of numbers, skips zero, and prints other numbers.\n\n```bash\n#!/bin/bash\nnumbers=(5 0 3 7)\nfor n in \"${numbers[@]}\"; do\n    if (( n == 0 )); then\n        continue\n    fi\n    echo \"Number: $n\"\ndone\n```\n\nExplanation:\n- continue skips the current iteration when number is zero.\n- Prints only non-zero numbers."
			},
			{
				question: "Loop with Break (stop on negative)",
				answer: "Write a shell script that loops through an array of numbers and stops the loop if a negative number is found.\n\n```bash\n#!/bin/bash\nnumbers=(5 3 -2 8)\nfor n in \"${numbers[@]}\"; do\n    if (( n < 0 )); then\n        echo \"Negative number found, stopping loop.\"\n        break\n    fi\n    echo \"Number: $n\"\ndone\n```\n\nExplanation:\n- break exits the loop immediately when a negative number is found.\n- Positive numbers before the negative number are printed."
			}
        
		// Add Shell Coding Q&A items here
	],

    // Categorized Shell questions
    shellCategories: {
        arrays: [
            { question: "Create and print array elements", answer: "```bash\n#!/bin/bash\narr=(10 20 30 40 50)\necho \"All elements: ${arr[@]}\"\necho \"Total count: ${#arr[@]}\"\n```\n\nExplanation:\n- arr=(...) initializes an array.\n- ${arr[@]} prints all elements.\n- ${#arr[@]} gives the number of elements." },
            { question: "Read 5 numbers into array and print 2nd", answer: "```bash\n#!/bin/bash\nnums=()\nfor i in {1..5};\ndo\n    read -p \"Enter number $i: \" n\n    nums+=(\"$n\")\ndone\n\necho \"All elements: ${nums[@]}\"\necho \"Second element: ${nums[1]}\"\n```\n\nExplanation:\n- Loops to read user input.\n- nums+=(\"$n\") appends to array.\n- Access elements using index." },
            { question: "Sum array elements", answer: "```bash\n#!/bin/bash\narr=(3 5 7)\nsum=0\nfor n in \"${arr[@]}\"; do\n    ((sum+=n))\ndone\necho \"Sum: $sum\"\n```\n\nExplanation:\n- Iterates through array to compute sum.\n- ((sum+=n)) adds each element." },
            { question: "Find max in array", answer: "```bash\n#!/bin/bash\narr=(5 12 3 9)\nmax=${arr[0]}\nfor n in \"${arr[@]}\"; do\n    (( n>max )) && max=$n\ndone\necho \"Max: $max\"\n```\n\nExplanation:\n- Initialize max with first element.\n- Compare each element, update max if larger." },
            { question: "Reverse print array", answer: "```bash\n#!/bin/bash\narr=(a b c d)\nfor ((i=${#arr[@]}-1;i>=0;i--)); do\n    echo ${arr[$i]}\ndone\n```\n\nExplanation:\n- ${#arr[@]} gives array length.\n- Loop decrements to print in reverse." }
        ],
        fileParsing: [
            { question: "Search CSV by ID", answer: "```bash\n#!/bin/bash\nset -euo pipefail\nread -rp \"Enter ID: \" id\nfound=0\nwhile IFS=',' read -r cid name age; do\n    if [[ \"$cid\" == \"$id\" ]]; then\n        printf \"%s,%s\\n\" \"$name\" \"$age\"\n        found=1\n        break\n    fi\ndone < <(tail -n +2 users.csv)\nif [[ $found -eq 0 ]]; then\n    echo \"ID not found\" >&2\n    exit 1\nfi\n```\n\nExplanation:\n- Reads CSV safely and splits fields by ,.\n- Skips header with tail -n +2.\n- Prints name and age for matching ID.\n- Exits if ID not found." },
            { question: "Search CSV by ID (with sample file)", answer: "```bash\n#!/bin/bash\n# Create sample CSV\necho -e \"ID,Name,Age\\n1,Alice,23\\n2,Bob,25\\n3,Charlie,22\" > users.csv\nread -p \"Enter ID to find: \" search_id\nwhile IFS=',' read -r id name age; do\n    if [[ $id == \"$search_id\" ]]; then\n        echo \"Name: $name, Age: $age\"\n        break\n    fi\ndone < <(tail -n +2 users.csv)\n```\n\nExplanation:\n- Demonstrates file creation, reading, and search in CSV." },
            { question: "Count lines in file", answer: "```bash\n#!/bin/bash\necho \"Lines: $(wc -l < file.txt)\"\n```\n\nExplanation: Counts total lines using wc -l." },
            { question: "List unique names from CSV", answer: "```bash\n#!/bin/bash\ntail -n +2 users.csv | cut -d, -f2 | sort -u\n```\n\nExplanation:\n- Skips header, extracts second column, sorts uniquely." },
            { question: "Filter age > 30 from CSV", answer: "```bash\n#!/bin/bash\ntail -n +2 users.csv | awk -F, '$3>30 {print $2, $3}'\n```\n\nExplanation: Uses awk to filter rows where age > 30." },
            { question: "Replace commas with tabs", answer: "```bash\n#!/bin/bash\nsed 's/,/\\t/g' users.csv > users.tsv\n```\n\nExplanation: Converts CSV to TSV using sed." }
        ],
        ifElse: [
            { question: "Even or odd", answer: "```bash\n#!/bin/bash\nread -p \"Enter n: \" n\nif (( n%2==0 )); then\n    echo Even\nelse\n    echo Odd\nfi\n```\n\nExplanation: Checks divisibility by 2." },
            { question: "File exists?", answer: "```bash\n#!/bin/bash\nread -p \"File path: \" p\nif [[ -f $p ]]; then\n    echo Exists\nelse\n    echo Missing\nfi\n```\n\nExplanation: Checks if a file exists." },
            { question: "String empty check", answer: "```bash\n#!/bin/bash\nread -p \"Enter text: \" s\nif [[ -z $s ]]; then\n    echo Empty\nelse\n    echo \"You typed: $s\"\nfi\n```\n\nExplanation: -z checks if string is empty." },
            { question: "Number compare", answer: "```bash\n#!/bin/bash\nread -p \"Enter n: \" n\nif (( n>10 )); then\n    echo \">10\"\nelif (( n==10 )); then\n    echo \"=10\"\nelse\n    echo \"<10\"\nfi\n```\n\nExplanation: Uses if-elif-else for numeric comparison." },
            { question: "Divisible by 3 and 5", answer: "```bash\n#!/bin/bash\nread -p \"Enter n: \" n\nif (( n%15==0 )); then\n    echo FizzBuzz\nfi\n```\n\nExplanation: Checks divisibility by 15." }
        ],
        loopsContinue: [
            { question: "Skip zeros", answer: "```bash\n#!/bin/bash\narr=(5 0 3 7)\nfor n in \"${arr[@]}\"; do\n    (( n==0 )) && continue\n    echo \"$n\"\ndone\n```\n\nExplanation: Skips zero elements using continue." },
            { question: "Skip comments in file", answer: "```bash\n#!/bin/bash\nwhile read -r line; do\n    [[ $line == \\#* ]] && continue\n    echo \"$line\"\ndone < file.txt\n```\n\nExplanation: Skips lines starting with #." },
            { question: "Print 1..10 except multiples of 3", answer: "```bash\n#!/bin/bash\nfor ((i=1;i<=10;i++)); do\n    (( i%3==0 )) && continue\n    echo $i\ndone\n```\n\nExplanation: Loops from 1 to 10, skips multiples of 3." },
            { question: "Skip empty lines", answer: "```bash\n#!/bin/bash\nwhile read -r l; do\n    [[ -z $l ]] && continue\n    echo $l\ndone < file.txt\n```\n\nExplanation: Skips blank lines." },
            { question: "Skip negative numbers", answer: "```bash\n#!/bin/bash\narr=(1 -2 4 -1 3)\nfor n in \"${arr[@]}\"; do\n    (( n<0 )) && continue\n    echo $n\ndone\n```\n\nExplanation: Skips negative numbers." }
        ],
        loopsBreak: [
            { question: "Stop on negative", answer: "```bash\n#!/bin/bash\narr=(5 3 -2 8)\nfor n in \"${arr[@]}\"; do\n    if (( n<0 )); then\n        echo stop\n        break\n    fi\n    echo $n\ndone\n```\n\nExplanation: Exits loop when a negative number is found." },
            { question: "Find first even", answer: "```bash\n#!/bin/bash\narr=(5 7 9 4 3)\nfor n in \"${arr[@]}\"; do\n    if (( n%2==0 )); then\n        echo $n\n        break\n    fi\ndone\n```\n\nExplanation: Prints the first even number and stops." },
            { question: "Read until 'quit'", answer: "```bash\n#!/bin/bash\nwhile read -p \"cmd> \" c; do\n    [[ $c == quit ]] && break\n    echo \"You: $c\"\ndone\n```\n\nExplanation: Loops until user types 'quit'." },
            { question: "Search word in file and stop", answer: "```bash\n#!/bin/bash\nwhile read -r l; do\n    echo $l | grep -q hello && { echo found; break; }\ndone < file.txt\n```\n\nExplanation: Stops reading once 'hello' is found." },
            { question: "Break after 5 iterations", answer: "```bash\n#!/bin/bash\ncount=0\nwhile true; do\n    echo $count\n    ((count++))\n    ((count==5)) && break\ndone\n```\n\nExplanation: Breaks loop after 5 iterations." }
        ]
    },
    deadlock: [
        {
            question: "Define Deadlock.",
            answer: "A state where processes are blocked forever, each waiting for resources held by others."
        },
        {
            question: "Four Necessary Conditions for Deadlock:",
            answer: "Mutual Exclusion – Resources cannot be shared.\nHold & Wait – Process holds at least one resource while requesting others.\nNo Preemption – Resources cannot be forcibly taken.\nCircular Wait – Processes form a circular chain of waiting."
        },
        {
            question: "Four Necessary Conditions for Deadlock (Detailed)",
            answer: "Mutual Exclusion\nAt least one resource must be non-shareable. Only one process can use the resource at a time.\nExample: A printer can be used by only one process at a time.\n\nHold and Wait\nA process is holding at least one resource and is waiting to acquire additional resources that are currently held by other processes.\nExample: Process P1 holds a printer and waits for a scanner held by P2.\n\nNo Preemption\nResources cannot be forcibly taken from a process. They must be released voluntarily.\nExample: Memory allocated to a process cannot be taken away until the process releases it.\n\nCircular Wait\nThere exists a set of processes {P1, P2, …, Pn} such that each process is waiting for a resource held by the next process in the set, forming a circle.\nExample: P1 → P2 → P3 → P1 (cycle of waiting)."
        },
        {
            question: "Explain Four Necessary Conditions for Deadlock",
            answer: "The four necessary conditions for deadlock are fundamental requirements that must all be present simultaneously for a deadlock to occur. Understanding these conditions helps in preventing and detecting deadlocks.\n\n1. Mutual Exclusion\nAt least one resource must be non-shareable. Only one process can use the resource at a time.\nExample: A printer can be used by only one process at a time.\n\n2. Hold and Wait\nA process is holding at least one resource and is waiting to acquire additional resources that are currently held by other processes.\nExample: Process P1 holds a printer and waits for a scanner held by P2.\n\n3. No Preemption\nResources cannot be forcibly taken from a process. They must be released voluntarily.\nExample: Memory allocated to a process cannot be taken away until the process releases it.\n\n4. Circular Wait\nThere exists a set of processes {P1, P2, …, Pn} such that each process is waiting for a resource held by the next process in the set, forming a circle.\nExample: P1 → P2 → P3 → P1 (cycle of waiting).\n\nKey Point: All four conditions must be present for deadlock to occur. Preventing any one of these conditions can prevent deadlock."
        },
        {
            question: "Deadlock Handling Methods:",
            answer: "Prevention: Prevent at least one necessary condition.\nAvoidance: Allocate resources carefully (Banker's Algorithm).\nDetection & Recovery: Detect deadlock, abort process or preempt resources.\nIgnore: \"Ostrich Algorithm\" for simple OS."
        },
        {
            question: "Safe vs Unsafe State:",
            answer: "Safe: Exists a sequence allowing all processes to finish.\nUnsafe: No guarantee; may or may not lead to deadlock."
        },
        {
            question: "Resource-Allocation Graph (RAG):",
            answer: "Request Edge: P → R (process requests resource)\nAssignment Edge: R → P (resource allocated)\nDeadlock Detection: Cycle in graph → deadlock exists"
        },
        {
            question: "Deadlock Prevention Example:",
            answer: "Prevent Hold & Wait by requesting all resources at once.\nImpact: May reduce resource utilization or cause starvation."
        },
        {
            question: "Circular Wait Prevention:",
            answer: "Impose global resource ordering.\nAcquire resources in a fixed order to prevent cycles and deadlocks."
        },
        {
            question: "Banker's Algorithm (Math Example)",
            answer: "Table Format (5 columns):\nProcess | Max (A,B,C) | Allocation (A,B,C) | Need (A,B,C) | Available (A,B,C)\nP0 | 7,5,3 | 0,1,0 | 7,4,3 | 3,3,2\nP1 | 3,2,2 | 2,0,0 | 1,2,2 | 3,3,2\nP2 | 9,0,2 | 3,0,2 | 6,0,0 | 3,3,2\nP3 | 2,2,2 | 2,1,1 | 0,1,1 | 3,3,2\nP4 | 4,3,3 | 0,0,2 | 4,3,1 | 3,3,2\n\nSafety Sequence: P1 → P3 → P0 → P2 → P4\n\nResource Request Example:\nP1 requests (1,0,2)\nCheck: Request ≤ Need and ≤ Available → Yes\nPretend allocation → Run safety algorithm → Safe\nResult: Request granted, system remains safe\n\nExplanation:\nEnsures resources are granted only if the system remains safe.\nPrevents deadlocks while allowing multiple processes to share resources."
        }
    ]
};

// DOM Elements
const topicSelect = document.getElementById('topicSelect');
const qaContainer = document.getElementById('qaContainer');
let shellButtonsWrapper = null; // container for shell category buttons
let selectedShellCategory = '';

// Function to format answer text with proper table formatting
function formatAnswer(answer) {
    // Split answer into lines
    const lines = answer.split('\n');
    let formatted = '';
    let inTable = false;
    let tableRows = [];
    // Code block parsing (supports fenced ``` and bash shebang blocks)
    let inCode = false;
    let codeLang = 'bash';
    let codeLines = [];

    const flushTable = () => {
        if (inTable && tableRows.length > 0) {
            formatted += createTable(tableRows);
            tableRows = [];
            inTable = false;
        }
    };

    const flushCode = () => {
        if (inCode && codeLines.length > 0) {
            formatted += createCodeBlock(codeLines.join('\n'), codeLang);
            codeLines = [];
            inCode = false;
            codeLang = 'bash';
        }
    };

    for (let i = 0; i < lines.length; i++) {
        const rawLine = lines[i];
        const line = rawLine.trim();

        // Handle fenced code blocks: ``` or ```lang
        if (line.startsWith('```')) {
            const lang = line.slice(3).trim();
            if (!inCode) {
                // Opening fence
                flushTable();
                inCode = true;
                codeLang = lang || 'bash';
                codeLines = [];
            } else {
                // Closing fence
                flushCode();
            }
            continue;
        }

        // Handle shebang-started bash blocks (collect until blank line)
        if (!inCode && line.startsWith('#!/bin/bash')) {
            flushTable();
            inCode = true;
            codeLang = 'bash';
            codeLines = [rawLine];
            continue;
        }
        if (inCode && codeLang === 'bash') {
            // End bash shebang block on empty separating line
            if (line === '') {
                flushCode();
                formatted += '\n';
            } else {
                codeLines.push(rawLine);
            }
            continue;
        }

        // Check if this line is part of a table (contains |)
        if (line.includes('|') && line.split('|').length > 1) {
            if (!inTable) {
                inTable = true;
                tableRows = [];
            }
            tableRows.push(line);
        } else {
            // If we were in a table, close it
            flushTable();
            formatted += line + '\n';
        }
    }
    
    // Close any remaining table or code block
    flushTable();
    flushCode();
    
    return formatted;
}

// Function to create HTML table from rows
function createTable(rows) {
    if (rows.length === 0) return '';
    
    const tableHtml = `
        <table class="w-full border-collapse border border-gray-600 my-4 text-sm">
            <tbody>
                ${rows.map(row => {
                    const cells = row.split('|').map(cell => cell.trim());
                    return `<tr>${cells.map(cell => `<td class="border border-gray-600 px-3 py-2">${cell}</td>`).join('')}</tr>`;
                }).join('')}
            </tbody>
        </table>
    `;
    return tableHtml;
}

// Function to wrap code with syntax highlighting and a copy button
function createCodeBlock(code, language = 'bash') {
    const safeCode = code.replace(/&/g, '&amp;')
                         .replace(/</g, '&lt;')
                         .replace(/>/g, '&gt;');
    const id = 'code-' + Math.random().toString(36).slice(2);
    return `
        <div class="relative bg-[#0b0b0b] border border-gray-800 rounded-md overflow-hidden my-4">
            <div class="absolute right-2 top-2">
                <button class="copy-btn text-xs px-2 py-1 border border-gray-700 rounded text-gray-300 hover:bg-gray-800" data-target="${id}">Copy code</button>
            </div>
            <pre class="m-0 p-4 overflow-auto"><code id="${id}" class="language-${language}">${safeCode}</code></pre>
        </div>
    `;
}

// Function to add a new Q&A to a specific topic
function addQA(topic, question, answer) {
    if (qaData[topic]) {
        qaData[topic].push({ question, answer });
        // If this topic is currently selected, refresh the display
        if (topicSelect.value === topic) {
            displayQA(topic);
        }
    }
}

// Function to display Q&A for selected topic
function displayQA(topic) {
    // Handle Shell sub-categories via a row of buttons
    if (topic === 'shell') {
        ensureShellCategoryButtons();
        if (!selectedShellCategory) {
            // Default to Arrays so users immediately see content
            selectedShellCategory = 'arrays';
            updateShellButtonsActive();
        }
        const questions = (qaData.shellCategories && qaData.shellCategories[selectedShellCategory]) || [];
        const generalShellItems = qaData.shell || [];
        if (questions.length === 0 && generalShellItems.length === 0) {
            qaContainer.innerHTML = `
                <div class="text-center py-16 text-gray-500">
                    <p>No questions available</p>
                </div>
            `;
            return;
        }
        const categoryHtml = questions.map((qa, index) => `
            <div class="mb-8 pb-8 border-b border-gray-800">
                <div class="mb-4">
                    <h3 class="text-lg font-medium text-white mb-3">Q${index + 1}. ${qa.question}</h3>
                    <div class="text-gray-400 leading-relaxed whitespace-pre-line">${formatAnswer(qa.answer)}</div>
                </div>
            </div>
        `).join('');
        const generalHtml = generalShellItems.length > 0 ? (`
            <div class="mt-6 mb-2 text-sm text-gray-500">General Shell Questions</div>
            ${generalShellItems.map((qa, idx) => `
                <div class="mb-8 pb-8 border-b border-gray-800">
                    <div class="mb-4">
                        <h3 class="text-lg font-medium text-white mb-3">${qa.question}</h3>
                        <div class="text-gray-400 leading-relaxed whitespace-pre-line">${formatAnswer(qa.answer)}</div>
                    </div>
                </div>
            `).join('')}
        `) : '';
        qaContainer.innerHTML = categoryHtml + generalHtml;
        return;
    }

    // Remove shell buttons if present for other topics
    removeShellCategoryButtons();

    const questions = qaData[topic] || [];

    // If showing Coding, render normally (like other topics)
    if (topic === 'coding') {
        if (questions.length === 0) {
            qaContainer.innerHTML = `
                <div class="text-center py-16 text-gray-500">
                    <p>No questions available</p>
                </div>
            `;
            return;
        }
        qaContainer.innerHTML = questions.map((qa, index) => `
            <div class="mb-8 pb-8 border-b border-gray-800">
                <div class="mb-4">
                    <h3 class="text-lg font-medium text-white mb-3">Q${index + 1}. ${qa.question}</h3>
                    <div class="text-gray-400 leading-relaxed whitespace-pre-line">${formatAnswer(qa.answer)}</div>
                </div>
            </div>
        `).join('');
        return;
    }

    if (questions.length === 0) {
        qaContainer.innerHTML = `
            <div class="text-center py-16 text-gray-500">
                <p>No questions available</p>
            </div>
        `;
        return;
    }

    qaContainer.innerHTML = questions.map((qa, index) => `
        <div class="mb-8 pb-8 border-b border-gray-800">
            <div class="mb-4">
                <h3 class="text-lg font-medium text-white mb-3">Q${index + 1}. ${qa.question}</h3>
                <div class="text-gray-400 leading-relaxed whitespace-pre-line">${formatAnswer(qa.answer)}</div>
            </div>
        </div>
    `).join('');
}

// Ensure Shell subtype select exists (Arrays, File Parsing, If-Else, Continue, Break)
function ensureShellCategoryButtons() {
    if (shellButtonsWrapper) return;
    shellButtonsWrapper = document.createElement('div');
    shellButtonsWrapper.className = 'mb-6 flex flex-wrap gap-2';
    const categories = [
        { key: 'arrays', label: 'Arrays' },
        { key: 'fileParsing', label: 'File Parsing' },
        { key: 'ifElse', label: 'If-Else' },
        { key: 'loopsContinue', label: 'Loops - Continue' },
        { key: 'loopsBreak', label: 'Loops - Break' }
    ];
    categories.forEach(cat => {
        const btn = document.createElement('button');
        btn.textContent = cat.label;
        btn.setAttribute('data-key', cat.key);
        btn.className = 'px-3 py-1 border border-gray-700 text-gray-300 rounded hover:bg-gray-800';
        btn.addEventListener('click', () => {
            selectedShellCategory = cat.key;
            updateShellButtonsActive();
            displayQA('shell');
        });
        shellButtonsWrapper.appendChild(btn);
    });
    topicSelect.parentElement.insertAdjacentElement('afterend', shellButtonsWrapper);
    updateShellButtonsActive();
}

function updateShellButtonsActive() {
    if (!shellButtonsWrapper) return;
    const buttons = shellButtonsWrapper.querySelectorAll('button[data-key]');
    buttons.forEach(btn => {
        const isActive = btn.getAttribute('data-key') === selectedShellCategory;
        btn.className = 'px-3 py-1 border rounded ' + (isActive
            ? 'border-gray-600 bg-gray-800 text-white'
            : 'border-gray-700 text-gray-300 hover:bg-gray-800');
    });
}

function removeShellCategoryButtons() {
    if (!shellButtonsWrapper) return;
    shellButtonsWrapper.parentElement.removeChild(shellButtonsWrapper);
    shellButtonsWrapper = null;
    selectedShellCategory = '';
}

// Event listener for topic selection
topicSelect.addEventListener('change', function() {
    const selectedTopic = this.value;
    if (selectedTopic) {
        displayQA(selectedTopic);
    } else {
        qaContainer.innerHTML = `
            <div class="text-center py-16 text-gray-500">
                <p>Select a topic</p>
            </div>
        `;
    }
});

// Initialize display
qaContainer.innerHTML = `
    <div class="text-center py-16 text-gray-500">
        <p>Select a topic</p>
    </div>
`;

// Export function for adding Q&A (for external use)
window.addQA = addQA;
