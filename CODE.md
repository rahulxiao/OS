# 📌 Shell Scripting Examples with Explanations

This document contains **questions and answers for arrays, file parsing, if-else, loops with continue, and loops with break** in shell scripting, along with clear explanations.

---

## **1️⃣ Arrays**

1. **Create and print array elements**

```bash
#!/bin/bash
arr=(10 20 30 40 50)
echo "All elements: ${arr[@]}"
echo "Total count: ${#arr[@]}"
```

**Explanation:**

* `arr=(...)` initializes an array.
* `${arr[@]}` prints all elements.
* `${#arr[@]}` gives the number of elements.

2. **Read 5 numbers into array and print 2nd**

```bash
#!/bin/bash
nums=()
for i in {1..5}; do
    read -p "Enter number $i: " n
    nums+=("$n")
 done
 echo "All elements: ${nums[@]}"
 echo "Second element: ${nums[1]}"
```

**Explanation:**

* Loops to read user input.
* `nums+=("$n")` appends to array.
* Access elements using index.

3. **Sum array elements**

```bash
#!/bin/bash
arr=(3 5 7)
sum=0
for n in "${arr[@]}"; do
    ((sum+=n))
done
 echo "Sum: $sum"
```

**Explanation:**

* Iterates through array to compute sum.
* `((sum+=n))` adds each element.

4. **Find max in array**

```bash
#!/bin/bash
arr=(5 12 3 9)
max=${arr[0]}
for n in "${arr[@]}"; do
    (( n>max )) && max=$n
done
 echo "Max: $max"
```

**Explanation:**

* Initialize `max` with first element.
* Compare each element, update max if larger.

5. **Reverse print array**

```bash
#!/bin/bash
arr=(a b c d)
for ((i=${#arr[@]}-1;i>=0;i--)); do
    echo ${arr[$i]}
done
```

**Explanation:**

* `${#arr[@]}` gives array length.
* Loop decrements to print in reverse.

---

## **2️⃣ File Parsing**

1. **Search CSV by ID**

```bash
#!/bin/bash
set -euo pipefail
read -rp "Enter ID: " id
found=0
while IFS=',' read -r cid name age; do
    if [[ "$cid" == "$id" ]]; then
        printf "%s,%s\n" "$name" "$age"
        found=1
        break
    fi
done < <(tail -n +2 users.csv)
if [[ $found -eq 0 ]]; then
    echo "ID not found" >&2
    exit 1
fi
```

**Explanation:**

* Reads CSV safely and splits fields by `,`.
* Skips header with `tail -n +2`.
* Prints name and age for matching ID.
* Exits if ID not found.

2. **Search CSV by ID with sample file**

```bash
#!/bin/bash
# Create sample CSV
echo -e "ID,Name,Age\n1,Alice,23\n2,Bob,25\n3,Charlie,22" > users.csv
read -p "Enter ID to find: " search_id
while IFS=',' read -r id name age; do
    if [[ $id == "$search_id" ]]; then
        echo "Name: $name, Age: $age"
        break
    fi
done < <(tail -n +2 users.csv)
```

**Explanation:**

* Demonstrates file creation, reading, and search in CSV.

3. **Count lines in file**

```bash
#!/bin/bash
echo "Lines: $(wc -l < file.txt)"
```

**Explanation:** Counts total lines using `wc -l`.

4. **List unique names from CSV**

```bash
#!/bin/bash
tail -n +2 users.csv | cut -d, -f2 | sort -u
```

**Explanation:**

* Skips header, extracts second column, sorts uniquely.

5. **Filter age > 30 from CSV**

```bash
#!/bin/bash
tail -n +2 users.csv | awk -F, '$3>30 {print $2, $3}'
```

**Explanation:** Uses `awk` to filter rows where age > 30.

6. **Replace commas with tabs**

```bash
#!/bin/bash
sed 's/,/\t/g' users.csv > users.tsv
```

**Explanation:** Converts CSV to TSV using `sed`.

---

## **3️⃣ If-Else Statements**

1. **Even or odd**

```bash
#!/bin/bash
read -p "Enter n: " n
if (( n%2==0 )); then echo Even; else echo Odd; fi
```

**Explanation:** Checks divisibility by 2.

2. **File exists?**

```bash
#!/bin/bash
read -p "File path: " p
if [[ -f $p ]]; then echo Exists; else echo Missing; fi
```

**Explanation:** Checks if a file exists.

3. **String empty check**

```bash
#!/bin/bash
read -p "Enter text: " s
if [[ -z $s ]]; then echo Empty; else echo "You typed: $s"; fi
```

**Explanation:** `-z` checks if string is empty.

4. **Number compare**

```bash
#!/bin/bash
read -p "Enter n: " n
if (( n>10 )); then echo ">10"; elif (( n==10 )); then echo "=10"; else echo "<10"; fi
```

**Explanation:** Uses if-elif-else for numeric comparison.

5. **Divisible by 3 and 5**

```bash
#!/bin/bash
read -p "Enter n: " n
if (( n%15==0 )); then echo FizzBuzz; fi
```

**Explanation:** Checks divisibility by 15.

---

## **4️⃣ Loops with Continue**

1. **Skip zeros**

```bash
#!/bin/bash
arr=(5 0 3 7)
for n in "${arr[@]}"; do
    (( n==0 )) && continue
    echo "$n"
done
```

**Explanation:** Skips zero elements using `continue`.

2. **Skip comments in file**

```bash
#!/bin/bash
while read -r line; do
    [[ $line == \#* ]] && continue
    echo "$line"
done < file.txt
```

**Explanation:** Skips lines starting with `#`.

3. **Print 1..10 except multiples of 3**

```bash
#!/bin/bash
for ((i=1;i<=10;i++)); do
    (( i%3==0 )) && continue
    echo $i
done
```

**Explanation:** Loops from 1 to 10, skips multiples of 3.

4. **Skip empty lines**

```bash
#!/bin/bash
while read -r l; do
    [[ -z $l ]] && continue
    echo $l
done < file.txt
```

**Explanation:** Skips blank lines.

5. **Skip negative numbers**

```bash
#!/bin/bash
arr=(1 -2 4 -1 3)
for n in "${arr[@]}"; do
    (( n<0 )) && continue
    echo $n
done
```

**Explanation:** Skips negative numbers.

---

## **5️⃣ Loops with Break**

1. **Stop on negative**

```bash
#!/bin/bash
arr=(5 3 -2 8)
for n in "${arr[@]}"; do
    if (( n<0 )); then
        echo stop
        break
    fi
    echo $n
done
```

**Explanation:** Exits loop when a negative number is found.

2. **Find first even**

```bash
#!/bin/bash
arr=(5 7 9 4 3)
for n in "${arr[@]}"; do
    if (( n%2==0 )); then
        echo $n
        break
    fi
done
```

**Explanation:** Prints the first even number and stops.

3. **Read until 'quit'**

```bash
#!/bin/bash
while read -p "cmd> " c; do
    [[ $c == quit ]] && break
    echo "You: $c"
done
```

**Explanation:** Loops until user types 'quit'.

4. **Search word in file and stop**

```bash
#!/bin/bash
while read -r l; do
    echo $l | grep -q hello && { echo found; break; }
done < file.txt
```

**Explanation:** Stops reading once 'hello' is found.

5. **Break after 5 iterations**

```bash
#!/bin/bash
count=0
while true; do
    echo $count
    ((count++))
    ((count==5)) && break
done
```

**Explanation:** Breaks loop after 5 iterations.
