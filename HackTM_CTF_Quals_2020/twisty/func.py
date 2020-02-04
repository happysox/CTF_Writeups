import random
def f(a):
 d = len(a)
 r = []
 def V(j, b = -1):
  b %= d
  if d - b < b:
   for k in range(d - b):
    if r and r[-1] == "U%d" % j:r.pop()
    else:r.append("D%d" % j)
    b = a[-1][j]
    for i in range(len(a) - 1):
     a[-1 - i][j] = a[-2 - i][j]
    a[0][j] = b
  else:
   for k in range(b):
    if r and r[-1] == "D%d" % j:r.pop()
    else:r.append("U%d" % j)
    b = a[0][j]
    for i in range(len(a) - 1):
     a[i][j] = a[i + 1][j]
    a[-1][j] = b
 def H(i, b = -1):
  b %= d
  if d - b < b:
   for k in range(d - b):
    if r and r[-1] == "L%d" % i:r.pop()
    else:r.append("R%d" % i)
    a[i] = a[i][-1:] + a[i][:-1]
  else:
   for k in range(b):
    if r and r[-1] == "R%d" % i:r.pop()
    else:r.append("L%d" % i)
    a[i] = a[i][1:] + a[i][:1]
 b = sorted(sum(a, []))
 for i in range(d - 1):
  for j in range(d):
   c = b.pop(0)
   e = sum(a, []).index(c)
   if e / d == i:
    if j == 0:H(i, e - j)
    elif j < e % d:
     if i:
      V(e % d, 1)
      H(i, j - e)
      V(e % d)
      H(i, e - j)
     else:
      V(e)
      H(1, e - j)
      V(j, 1)
   else:
    if j == e % d:
     H(e / d)
     e += 1
     if e % d == 0:e -= d
    if i:
     V(j, i - e / d)
    H(e / d, e - j)
    V(j, e / d - i)
 c = [b.index(e) for e in a[-1]]
 c = [sum(c[(i + j) % d] < c[(i + k) % d] for j in range(d) for k in range(j)) % 2 and d * d or sum(abs(c[(i + j) % d] - j) for j in range(d)) for i in range(d)]
 e = min(~c[::-1].index(min(c)), c.index(min(c)), key = abs)
 H(d - 1, e)
 for j in range(d - 2):
  e = a[-1].index(b[j])
  if e > j:
   c = b.index(a[-1][j])
   if c == e:
    if e - j == 1:c = j + 2
    else:c = j + 1
   V(e)
   H(d - 1, j - e)
   V(e, 1)
   H(d - 1, c - j)
   V(e)
   H(d - 1, e - c)
   V(e, 1)
 return r
