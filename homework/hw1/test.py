def r(num):
    cost = 0
    num.sort()
    while len(num) > 1:
    	print(len(num))
        sum = num.pop(0) + num.pop(1)
        cost+=sum
        num.append(sum)
        num.sort()
    return cost
