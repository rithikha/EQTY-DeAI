from eqty_sdk import init, DID, DID_ALGORITHMS, Dataset, Document, Computation, compute, generate_manifest, purge_integrity_store


# initialize the SDK 
init()

# create a new ED25519 DID and activate it
did = DID.new(
    DID_ALGORITHMS.ED25519,  # can change algo type
    name="My key", 
    description="My Ed25519 signing key for integrity statements." # active sig from here on out
)

did.set_active() # only one can be active at a time

#------------------------------------------------------------------------------------------------------------

my_object = {
    "data": [1, 2, 3],
    "text": "hello"
}

# Registering a serializable Python object
# SDK hashes and stores object in integrity store, assigns a CID, and records description in metadata
d0 = Dataset.from_object(
    my_object,
    name="My dataset 0",
    description="My description for dataset 0"
)
# d0 is an object instance now and can call on it attributes now e.g. d0.cid 

print("d0 CID=", d0.cid)

#------------------------------------------------------------------------------------------------------------

my_path = "/Users/rithikha/Documents/Dev/EQTY/explore/my_path_dataset.txt"

# Registering a file or directory of files from the file system
d1 = Document.from_path(
    my_path,
    name="My document 0",
    description="My description for dataset 1"
)

print("d1=", d1.cid)

#------------------------------------------------------------------------------------------------------------

my_cid = d0.cid

# Registering a data asset or collection of assets by its CID
d2 = Dataset.from_cid(
    my_cid,
    name="My data",
    description="My description for data",
    foo="bar" # arbitary metadata can be passed
)
print("d2=", d2.cid)

#------------------------------------------------------------------------------------------------------------


# “I ran some process that took these inputs and produced these outputs.” Only a provenance record, no actual computations are happening here
# buildign computation object -- it's not a real object, more like a state machine
computation = (
    Computation.new()
    .add_input_cid(d0.cid) 
    .add_input_cid(d1.cid) 
    .add_output_cid(d2.cid) 
)

# can lie here, same with incubment process. Right now we trust the social cpaital of the developer. app version example -- even on github if you 
# use github builder, it produces aritfacts in that it requires higher trust and we trust github that it wont lie about the buidl. but it doesnt 
# change the fact that the developer can uplaod a local build and then to the appstore and claim its the same version
# githbu is what we woudl calla hardened build system -- higher trust


# call finalize to register it (this writes and signs it, and sets a computation.cid which is why we call finalize first before print)
computation.finalize() # finalize returns none. builder pattern to assemble/puttign it all together, simply makign a json claim

    
state = computation.__getstate__()
print(state)


#------------------------------------------------------------------------------------------------------------

# remote compute job and its attributes
@compute(
    metadata={
        "name": "My computation",
        "description": "My description for the computation",
        "foo": "bar",
    }
)
# implicitly creatign a computation object/state machine
def my_function(input_0: Dataset, input_1: Dataset):
    my_output_object = input_0.value + input_1.value
    # registering the computation output 
    # data and computation, along with metadata registration statements will all be recorded
    output = Dataset.from_object(
        my_output_object,
        name="My dataset",
        description="My description for the output dataset"
    )
    # output should be 
    return output


generate_manifest("./manifest.json")
# purge_integrity_store() # will nuke local integrity data, remote records remain in the integrity store. will only stay local if .finalize() is never called.

# documentaitonal tool, not runnign any code for you. 