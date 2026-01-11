from pulp import (
    LpProblem, LpMinimize, LpVariable,
    lpSum, LpBinary, PULP_CBC_CMD
)
import time

# -----------------------------
# Parameters
# -----------------------------
r1 = 0
r2 = 7
r3 = 41

N = 64   # universe size

# -----------------------------
# Generate subsets T_j
# T_j = { j+r1, j+r2, j+r3 } mod 64
# -----------------------------
subsets = []

for j in range(N):
    Tj = {
        (j + r1) % N,
        (j + r2) % N,
        (j + r3) % N
    }
    subsets.append(sorted(Tj))

# -----------------------------
# Build universe and incidence
# -----------------------------
universe = set(range(N))
element_to_subsets = {e: [] for e in universe}

for idx, subset in enumerate(subsets):
    for elem in subset:
        element_to_subsets[elem].append(idx)

# -----------------------------
# Define ILP
# -----------------------------
prob = LpProblem("Set_Cover", LpMinimize)

x = [LpVariable(f"x_{i}", cat=LpBinary) for i in range(len(subsets))]

# Objective
prob += lpSum(x)

# Coverage constraints
for elem in universe:
    prob += lpSum(x[i] for i in element_to_subsets[elem]) >= 1

# -----------------------------
# Solve and measure time
# -----------------------------
start_time = time.time()
prob.solve(PULP_CBC_CMD(msg=0))
end_time = time.time()

# -----------------------------
# Output results
# -----------------------------
selected = [i for i in range(len(subsets)) if x[i].varValue == 1]

print("Solve time (seconds):", end_time - start_time)
print("Minimum number of subsets:", len(selected))
print("Selected subset indices:", selected)
print("Selected subsets:")
for i in selected:
    print(f"T_{i} =", subsets[i])

