from pulp import LpProblem, LpMinimize, LpVariable, lpSum, LpBinary, PULP_CBC_CMD

subsets = [
[0, 5, 24],
[1, 6, 25],
[2, 7, 26],
[3, 8, 27],
[4, 9, 28],
[5, 10, 29],
[6, 11, 30],
[7, 12, 31],
[8, 13, 16],
[9, 14, 17],
[10, 15, 18],
[0, 11, 19],
[1, 12, 20],
[2, 13, 21],
[3, 14, 22],
[4, 15, 23],
[2, 16, 21],
[3, 17, 22],
[4, 18, 23],
[5, 19, 24],
[6, 20, 25],
[7, 21, 26],
[8, 22, 27],
[9, 23, 28],
[10, 24, 29],
[11, 25, 30],
[12, 26, 31],
[13, 16, 27],
[14, 17, 28],
[15, 18, 29],
[0, 19, 30],
[1, 20, 31],
]

universe = set(range(32))
element_to_subsets = {e: [] for e in universe}
print(element_to_subsets)
for idx, subset in enumerate(subsets):
    for elem in subset:
        element_to_subsets[elem].append(idx)

prob = LpProblem("Set_Cover", LpMinimize)
x = [LpVariable(f"x_{i}", cat=LpBinary) for i in range(len(subsets))]
prob += lpSum(x)

for elem in universe:
    prob += lpSum(x[i] for i in element_to_subsets[elem]) >= 1

prob.solve(PULP_CBC_CMD(msg=0))

selected = [i for i in range(len(subsets)) if x[i].varValue == 1]
print("Minimum number of subsets:", len(selected))
print("Selected subset indices:", selected)
print("Selected subsets:")
for i in selected:
    print(subsets[i])

