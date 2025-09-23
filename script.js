// Q&A Data Structure
const qaData = {
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

// Function to format answer text with proper table formatting
function formatAnswer(answer) {
    // Split answer into lines
    const lines = answer.split('\n');
    let formatted = '';
    let inTable = false;
    let tableRows = [];
    
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        
        // Check if this line is part of a table (contains |)
        if (line.includes('|') && line.split('|').length > 1) {
            if (!inTable) {
                inTable = true;
                tableRows = [];
            }
            tableRows.push(line);
        } else {
            // If we were in a table, close it
            if (inTable && tableRows.length > 0) {
                formatted += createTable(tableRows);
                tableRows = [];
                inTable = false;
            }
            formatted += line + '\n';
        }
    }
    
    // Close any remaining table
    if (inTable && tableRows.length > 0) {
        formatted += createTable(tableRows);
    }
    
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
    const questions = qaData[topic] || [];
    
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
