# Distributed-Bloom-Filter

The Distributed Bloom Filter (DBF) is meant to be used in distributed systems that require set reconciliation between sets of nodes.

A DBF has three paramters: k, is the number of hashing functions, m , size of bit array, and SetSize, which is the number of elements in the set.

Because DBF is supposed to used in peer-to-peer systems in order to add elements to it, its need also an ID. Thus to add an element with hardcoded values (for a real usage check the examples directory):
```
dbf := disbf.New(10, 11)
node.ID = []byte("12345678901234567890123456789012")
otherNode := []byte("12345678901234567890123456789011")
element := []byte("Love")
dbf.Add(element, otherNode)
```
## Installation
```
go get github.com/arberiii/Distributed-Bloom-Filter 
```
## Making example

### Generate elements
In each example there are random elements for each node (intersection is possible).
Go to examples/scripts/generate/make_elements and open elements.go file, change the constant numbOFElements to the desire number, and then run
```
go run elements.go
```

### Generate test scenario
Go to examples/scripts/generate and open main.go file.
There are three constants:
1) numberOfServers, which is the number of servers used in test scenario.
2) numberOfNeigh, which is the number of neighbors for each peer assigned randomly.
3) noInitElements, which is the number of elements to be selected from the list of elements generated earlier.
Then run:
```
go run main.go
```

### Change the false positive rate
To change false positive rate go to bloom.go file, change the constant fpr and save the file.

### Run the test scenario
Go to examples/scripts, if neccesary make run_auto.sh executable and run
```
./run_auto.sh
```
If a peer converges, there will be the output that the peer has converged.

### Prepare the result to a csv file
Go to examples/scripts and run 
```
./prep.sh
```
