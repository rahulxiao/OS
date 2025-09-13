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
        }
    ],
    security: [
        {
            question: "Explain Four-Layered Security.",
            answer: "Physical Layer: Protects hardware using locks, CCTV, or restricted access.\nNetwork Layer: Protects data in transit using firewalls, VPNs, and intrusion detection systems (IDS).\nOperating System Layer: Manages authentication and access control.\nApplication Layer: Protects programs with secure coding, antivirus, and timely patches.\n\nExplanation:\nLayered security ensures defense-in-depth.\nIf one layer fails, others still protect the system."
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
