
const express = require('express');
const cors = require('cors');
require('dotenv').config();
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

const app = express();
const port = process.env.PORT || 5000;

// STRIPE RELETED REQUIRE
// const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY)
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY)


// const ACCESS_SECRET_TOKEN = process.env.ACCESS_SECRET_TOKEN;
const ACCESS_SECRET_TOKEN = process.env.ACCESS_SECRET_TOKEN;

app.use(cors({
    origin: ['http://localhost:5173', 'http://localhost:5174', 'http://localhost:5175', 'https://team-flow-48.web.app'],
    credentials: true
}));


app.use(express.json());
app.use(cookieParser());

const uri = `mongodb+srv://${process.env.TEMFLOW_USER_NAME}:${process.env.TEMFLOW_USER_PASS}@cluster0.ho6hi.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

// user verfiy with JWT token

const verifyWithToken = (req, res, next) => {
    const token = req.cookies?.token;

    if (!token) {
        return res.status(401).send({ message: 'Unauthorized access' });
    }

    jwt.verify(token, ACCESS_SECRET_TOKEN, (err, decode) => {
        if (err) {
            return res.status(401).send({ message: 'Unauthorized access' });
        }
        req.user = decode; // Attach decoded token (user info) to req.user
        next();
    });
};

// user verify with role
const verifyRole = (allowedRoles) => {
    return (req, res, next) => {
        const { role } = req.user;  // Now accessing role from req.user

        if (!role) {
            return res.status(403).send({ message: 'Forbidden: No role found in token' });
        }

        console.log('Decoded token role:', role); // Check the role

        // Convert both the allowed roles and the decoded role to lowercase for case-insensitive comparison
        const decodedRole = role.toLowerCase();
        const allowedRolesLower = allowedRoles.map(role => role.toLowerCase());

        if (!allowedRolesLower.includes(decodedRole)) {
            console.log(`Role mismatch. Allowed: ${allowedRoles}, Found: ${decodedRole}`);
            res.clearCookie('token', { httpOnly: true, secure: true }); // Optionally clear the token on mismatch
            return res.status(403).send({ message: 'Forbidden: Insufficient role. You have been logged out.' });
        }

        next(); // Role is valid, proceed
    };
};



async function run() {
    try {
        const db = client.db("TemFlow");
        const peopleCollection = db.collection('peopleCollection');
        const allTaskCollection = db.collection('allTaskCollection');
        // payroll collection 
        const payrollCollection = db.collection('payrollCollection')

        // STRIPE RELETED API
        app.post('/create-payment-intent', async (req, res) => {
            try {
                const { salary } = req.body; // Destructure salary from req.body
                const amount = parseInt(salary * 100); // Convert salary to cents
                console.log(amount);

                const paymentIntent = await stripe.paymentIntents.create({
                    amount: amount,
                    currency: 'usd',
                    payment_method_types: ['card']
                })

                res.send({ clientSecret: paymentIntent.client_secret });

            } catch (error) {
                console.error(error);
                res.status(500).send({ error: "Something went wrong" });
            }
        });


        // security releted api
        app.post('/jwt', (req, res) => {
            const { email, role } = req.body; // Extract the role from the request body

            if (!email) {
                return res.status(400).send({ message: 'Email and role are required' });
            }

            // Add the role explicitly to the payload
            const token = jwt.sign({ email, role }, ACCESS_SECRET_TOKEN, { expiresIn: '5h' });


            res.cookie('token', token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production', 
                sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
            }).send({ success: true });
        });


        app.post('/logout', (req, res) => {
            res.clearCookie('token', {
                httpOnly: true,
                secure: true,
                SameSite: 'None',
            });
        });

        // security releted api

        app.get('/register-people', verifyWithToken, verifyRole(['HR', 'admin', 'EMPLOYEE']), async (req, res) => {
            try {
                const cursoe = peopleCollection.find();
                const peoples = await cursoe.toArray();

                res.send(peoples);
            } catch (err) {
                res.status(500).send({ message: 'Error fetching all peoples data', err });
            }
        });

        app.get('/all-tasks', verifyWithToken, verifyRole(['HR', 'admin', 'EMPLOYEE']), async (req, res) => {
            try {
                const cursor = allTaskCollection.find();
                const tasks = await cursor.toArray();

                res.send(tasks);
            } catch (err) {
                res.status(500).send({ message: 'Error fetching all tasks data', err });
            }
        });

        app.get('/all-tasks/:email', verifyWithToken, verifyRole(['HR', 'EMPLOYEE']), async (req, res) => {
            const email = req.params.email;

            if (email.includes('@')) {
                try {
                    const currentUserTask = await allTaskCollection.find({ email: email }).toArray();

                    if (currentUserTask.length > 0) {
                        return res.send(currentUserTask);
                    } else {
                        return res.status(404).send({ message: "No Tutors found for this email" });
                    }
                } catch (error) {
                    console.error(error);
                    return res.status(500).send({ error: "Failed to fetch Tutors" });
                }
            } else {
                return res.status(400).send({ error: "Invalid email format" });
            }
        });

        app.get('/single-task/:id', verifyWithToken, async (req, res) => {
            const id = req.params.id;

            const query = { _id: new ObjectId(id) };
            const result = await allTaskCollection.findOne(query);
            res.send(result);
        });

        app.get('/register-people/:email', async (req, res) => {
            const email = req.params.email;

            // Improved email format validation
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                return res.status(400).send({ error: "Invalid email format" });
            }

            try {
                console.log(`Querying for email: ${email}`);

                // Use findOne if you expect a single document
                const loginUser = await peopleCollection.findOne({ email: email });

                if (loginUser) {
                    return res.send(loginUser);
                } else {
                    return res.status(404).send({ message: "No Tutors found for this email" });
                }
            } catch (error) {
                console.error("Database error:", error);
                return res.status(500).send({ error: error.message });
            }
        });


        app.get('/verified-employees', verifyWithToken, verifyRole(['admin','HR', 'EMPLOYEE']), async (req, res) => {
            try {
                const verifiedEmployees = await peopleCollection.find({ verified: true }).toArray();
                res.send(verifiedEmployees);
            } catch (error) {
                res.status(500).json({ error: 'Error fetching data' });
            }
        });

        // payroll colleciton data get only for admin
        app.get('/payroll-employee', verifyWithToken, verifyRole(['admin','HR', 'EMPLOYEE']),async (req, res) => {
            try {
                const payRollEmployee = await payrollCollection.find().toArray()
                res.send(payRollEmployee)
            } catch (err) {
                res.status(500).send({ Message: 'error to get payroll employee data', err })
            }
        })
        // get payroll data using email
        app.get('/payroll-employee/:email', verifyWithToken, async (req, res) => {
            const email = req.params.email;

            if (email.includes('@')) {
                try {
                    const paymentData = await payrollCollection.find({ email: email }).toArray();

                    if (paymentData.length > 0) {
                        return res.send(paymentData);
                    } else {
                        return res.status(404).send({ message: "No payment data found for this email" });
                    }
                } catch (error) {
                    console.error(error);
                    return res.status(500).send({ error: "Failed to fetch payment data" });
                }
            } else {
                return res.status(400).send({ error: "Invalid email format" });
            }
        });

        app.get('/payroll-employee-list/:id', async (req, res) => {
            const id = req.params.id;

            const query = { _id: new ObjectId(id) };
            const result = await payrollCollection.findOne(query);
            res.send(result);
        });


        app.put('/single-task/:id', verifyWithToken, async (req, res) => {
            const id = req.params.id;
            const filter = { _id: new ObjectId(id) };
            const option = { upsert: true };
            const updateTask = req.body;

            const update = {
                $set: {
                    task: updateTask.task,
                    hour: updateTask.hour,
                    date: updateTask.date,
                }
            };

            try {
                const result = await allTaskCollection.updateOne(filter, update, option);
                if (result.modifiedCount > 0) {
                    res.send(result);
                } else {
                    res.status(500).send({ error: 'Failed to update tutorials' });
                }
            } catch {
                res.status(500).send({ error: 'Failed to update tutorials' });
            }
        });

        // check usre role
        app.post('/check-user-role', async (req, res) => {
            try {
                const { email } = req.body;

                if (!email) {
                    return res.status(400).send({ message: "Email is required" });
                }

                const user = await peopleCollection.findOne({ email });

                if (!user) {
                    return res.status(404).send({ message: "User not found" });
                }

                // Check if the user has a role
                if (!user.role) {
                    return res.status(404).send({ message: "Role not found for the user" });
                }

                // Role exists
                res.status(200).send({
                    message: "User role found",
                    role: user.role
                });

            } catch (err) {
                console.error("Error checking user role:", err);
                res.status(500).send({ message: "Error checking user role", err });
            }
        });

        // check fire status
        app.post('/check-user-fired-status', async (req, res) => {
            try {
                const { email } = req.body;

                if (!email) {
                    return res.status(400).send({ message: "Email is required" });
                }

                const user = await peopleCollection.findOne({ email });

                if (!user) {
                    return res.status(404).send({ message: "User not found" });
                }

                if (user.isFired) {
                    return res.status(403).send({ message: "Your are fired! you can't login" });
                }

                res.status(200).send({
                    message: "You are allowed to login.",
                    user: {
                        email: user.email,
                        name: user.name,
                    }
                });

            } catch (err) {
                console.error("Error checking user fired status:", err);
                res.status(500).send({ message: "Error checking user fired status", err });
            }
        });

        app.post('/all-tasks', verifyWithToken, verifyRole(['employee']), async (req, res) => {
            const task = req.body;
            try {
                const result = await allTaskCollection.insertOne(task);
                res.send(result);
            }
            catch (err) {
                res.status(500).send({ Message: 'Faild to add food into cart' });
            }
        });

        app.patch('/user-verified/:id', verifyWithToken, verifyRole(['HR']), async (req, res) => {
            const id = req.params.id;
            const filter = { _id: new ObjectId(id) };

            try {
                const user = await peopleCollection.findOne(filter);

                if (!user) {
                    return res.status(404).send({ message: 'User not found' });
                }

                const newVerifiedStatus = !user.verified;

                const update = {
                    $set: {
                        verified: newVerifiedStatus
                    }
                };

                const result = await peopleCollection.updateOne(filter, update);

                if (result.modifiedCount === 1) {
                    res.send({ message: `User verification status updated to ${newVerifiedStatus ? 'verified' : 'unverified'}` });
                } else {
                    res.status(404).send({ message: 'User not found or no change in status' });
                }
            } catch (err) {
                res.status(500).send({ message: 'Error updating user verification', err });
            }
        });

        // admin api

        app.patch('/update-salary/:id', verifyWithToken, verifyRole(['admin']), async (req, res) => {
            const id = req.params.id;
            const filter = { _id: new ObjectId(id) };
            const newSalary = req.body.salary;

            if (newSalary === undefined) {
                return res.status(400).send({ message: 'New salary is required' });
            }

            try {
                const user = await peopleCollection.findOne(filter);

                if (!user) {
                    return res.status(404).send({ message: 'User not found' });
                }

                const update = {
                    $set: {
                        salary: newSalary
                    }
                };

                const result = await peopleCollection.updateOne(filter, update);

                if (result.modifiedCount === 1) {
                    res.send({ message: `Salary updated to ${newSalary}` });
                } else {
                    res.status(404).send({ message: 'User not found or no change in salary' });
                }
            } catch (err) {
                res.status(500).send({ message: 'Error updating salary', err });
            }
        });


        // update user role by admin only
        app.patch('/update-user-role/:id', verifyWithToken, verifyRole(['admin']), async (req, res) => {
            const id = req.params.id;
            const filter = { _id: new ObjectId(id) };
            const { role: userRole } = req.body; // Destructure role from req.body

            if (!userRole) {
                return res.status(400).send({ message: 'Role is required' });
            }

            try {
                const user = await peopleCollection.findOne(filter);

                if (!user) {
                    return res.status(404).send({ message: 'User not found' });
                }

                const update = {
                    $set: {
                        role: userRole,
                    }
                };

                const result = await peopleCollection.updateOne(filter, update);

                if (result.modifiedCount === 1) {
                    res.send({ message: `User role updated to ${userRole}` });
                } else {
                    res.status(400).send({ message: 'No changes made to user role' });
                }
            } catch (err) {
                res.status(500).send({ message: 'Error updating user role', err });
            }
        });

        // admin can firedn any employee or hr
        app.patch('/chenge-fired-status/:id', verifyWithToken, verifyRole(['admin']), async (req, res) => {
            const id = req.params.id;
            const filter = { _id: new ObjectId(id) };

            try {
                // Fetch the user document to ensure the user exists
                const user = await peopleCollection.findOne(filter);

                if (!user) {
                    return res.status(404).send({ message: 'User not found' });
                }

                // Toggle the fired status
                const firedStatus = !user.isFired;

                const update = {
                    $set: {
                        isFired: firedStatus
                    }
                };

                const result = await peopleCollection.updateOne(filter, update);

                if (result.modifiedCount === 1) {
                    res.send({ message: `User fired status updated to ${firedStatus}` });
                } else {
                    res.status(404).send({ message: 'User not found or no change in fired status' });
                }
            } catch (err) {
                res.status(500).send({ message: 'Error updating fired status', err });
            }
        });


        app.post('/register-people', async (req, res) => {
            const people = req.body;
            const email = people.email;

            // Check if email is provided
            if (!email) {
                return res.status(400).send({ error: "Email is required" });
            }

            try {
                // Check if the user already exists in the collection
                const existingUser = await peopleCollection.findOne({ email: email });

                if (existingUser) {
                    // If the user exists, check if they are fired
                    if (existingUser.isFired) {
                        // If the user is fired, prevent login or registration
                        return res.status(403).send({ message: "You are fired! You can't login." });
                    }

                    // If the user is not fired, allow login
                    return res.status(200).send({
                        message: "User exists and is allowed to login.",
                        user: {
                            email: existingUser.email,
                            name: existingUser.name,
                        }
                    });
                }

                // If the user doesn't exist, proceed with registration
                // Insert the new user into the collection
                const result = await peopleCollection.insertOne(people);

                // Return success response
                res.status(201).send({
                    message: "User registered successfully",
                    user: {
                        email: people.email,
                        name: people.name,
                        bankAccountNo: people.bankAccountNo,
                        salary: people.salary,
                        designation: people.designation,
                        role: people.role,
                        photo: people.photo,
                        isVerified: people.isVerified,
                        isFired: people.isFired,
                    }
                });
            } catch (error) {
                console.error(error);
                return res.status(500).send({ error: "Failed to register user or check fired status" });
            }
        });

        // payroll conllection data sotre
        app.post('/payroll', async (req, res) => {
            const payment = req.body;

            try {
                const result = await payrollCollection.insertOne(payment)
                res.send(result)
            } catch (err) {
                res.status(500).send({ message: 'Error insert payment information', err });
            }

        })

        // update payroll collection

        app.patch('/payroll/update-payment/:id', async (req, res) => {
            const id = req.params.id;
            const filter = { _id: new ObjectId(id) };

            // Extract the new transactionID and paymentDate from the request body
            const { transactionID, paymentDate } = req.body;

            try {
                // Fetch the user document to ensure the user exists
                const user = await payrollCollection.findOne(filter);

                if (!user) {
                    return res.status(404).send({ message: 'User not found' });
                }

                // Update the user with new transactionID and paymentDate
                const update = {
                    $set: {
                        transactionID: transactionID,
                        paymentDate: paymentDate
                    }
                };

                const result = await payrollCollection.updateOne(filter, update);

                if (result.modifiedCount === 1) {
                    res.send({ message: 'Payment information updated successfully' });
                } else {
                    res.status(404).send({ message: 'User not found or no change in payment information' });
                }
            } catch (err) {
                res.status(500).send({ message: 'Error updating payment information', err });
            }
        });

        // is request field when hr request to payment one time to admin
        app.patch('/chenge-pay-request-status/:id', verifyRole(['admin']), async (req, res) => {
            const id = req.params.id;
            const filter = { _id: new ObjectId(id) };

            // Extract the new transactionID and paymentDate from the request body
            const { isRequestForPay } = req.body;

            try {
                // Fetch the user document to ensure the user exists
                const user = await peopleCollection.findOne(filter);

                if (!user) {
                    return res.status(404).send({ message: 'User not found' });
                }

                // Update the user with new transactionID and paymentDate
                const update = {
                    $set: {
                        isRequestForPay: isRequestForPay
                    }
                };

                const result = await peopleCollection.updateOne(filter, update);

                if (result.modifiedCount === 1) {
                    res.send({ message: ' updated successfully' });
                } else {
                    res.status(404).send({ message: 'User not found or no change in payment information' });
                }
            } catch (err) {
                res.status(500).send({ message: 'Error updating payment information', err });
            }
        });



        // delete task. employee can delete task
        app.delete(
            '/task-delete/:id',
            verifyWithToken, 
            verifyRole(['employee']), 
            async (req, res) => {
                const id = req.params.id;
                const query = { _id: new ObjectId(id) };

                try {
                    const result = await allTaskCollection.deleteOne(query);
                    res.send({ success: true, message: 'Task deleted successfully', result });
                } catch (error) {
                    res.status(500).send({ success: false, message: 'Error deleting task', error });
                }
            }
        );


    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);


// connect with mongoDB


// basic get api
app.get('/', (req, res) => {
    res.send("TemFlow Basic server started..")
})

app.listen(port, () => {
    console.log("This server running on", port)
})