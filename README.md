# The Distributed Bloom Filter

The Distributed Bloom Filter is a space-efficient, probabilistic data structure designed to perform more efficient set reconciliations in distributed systems. It guarantees eventual consistency of states between nodes in a system, while still keeping bloom filter sizes as compact as possible. The eventuality can be tweaked as desired, by tweaking the distributed bloom filter’s parameters. The scalability, as well as accuracy of the data structure is made possible by combining two novel ideas: The first idea introduces a new, computationally inexpensive way for populating bloom filters, making it possible to quickly compute new bloom filters when interacting with peers. The second idea introduces the concept of unique bloom filter mappings between peers. By applying these two simple ideas, one can achieve incredibly bandwidth-efficient set reconciliation in networks. Instead of trying to minimize the false positive rate of a single bloom filter, we use the unique bloom filter mappings to increase the probability for an element to propagate through a network. For more information on the distributed bloom filter, please refer to the original [paper](https://arxiv.org/abs/1910.07782) 


## Example
To initiate a distributed bloom filter, we need to specify three parameters: *n*, *fpr*, and *s*. 
*n* is the number of elements that we want to insert into the distributed bloom filter, *fpr* is the false positive rate for our bloom filter, and *s* is an initial seed value that determines the bloom filter mapping. By specifying *n* and *fpr*, the DBF automatically determines the bloom filter size *m* and number of hash functions used *k*.
```
dbf := DBF.NewDbf(10, 0.5, []byte("seed"))
element := []byte("something")
dbf.Add(element)
```
## Installation
```
go get github.com/labbloom/DBF
```
### License
[Apache-2.0](https://github.com/labbloom/DBF/blob/master/LICENSE)