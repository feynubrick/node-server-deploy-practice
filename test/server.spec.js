'use strict'

var request = require('supertest');
var chai = require('chai');
var chaiHttp = require('chai-http');

var app = require('../app');
var expect = chai.expect;

chai.use(chaiHttp);

var agent = chai.request.agent(app);

/**
 * @description api test
 * */ 

describe('GET /', () => {
  it('should respond with Success message', (done) => {
    request(app)
      .get('/')
      .expect(200)
      .end((err, res) => {
        if(err) {
          done(err);
          return;
        }

        expect(res.text).to.equal('Success');
        done();
      })
  })
})

describe('POST /links', () => {
  it('should respond with Url', (done) => {
    request(app)
      .post('/links')
      .send({
        url: 'https://velopert.com'
      })
      .expect(201)
      .end((err, res) => {
        if(err) {
          done(err);
          return;
        }

        expect(res.body).has.all.keys([
          'id', 'url', 'baseUrl', 'title', 'visits', 'updatedAt', 'createdAt', 'code'
        ])

        expect(res.body.url).to.equal('https://velopert.com');
        // expect(res.body.title).to.equal('NAVER');
        expect(res.body.visits).to.equal(0);

        done();
      })
  })
})

describe('GET /links', () => {
  it('should respond with Url list', (done) => {
    request(app)
    .get('/links')
    .end((err, res) => {
        if(err) {
        done(err);
        return;
        }

        if(res.body.length) {
        expect(200)
        res.body.forEach((data_val, index) => {
            expect(data_val).has.all.keys([
            'id', 'url', 'baseUrl', 'title', 'visits', 'updatedAt', 'createdAt', 'code'
            ])
        })
        } else {
        expect(204)
        }

        done();
    })
  })
})

describe('GET /*', () => {
  it('should redirect Url to baseUrl + code', (done) => {
    request(app)
      .get('/c2c0c')
      .end((err, res) => {
        if(err) {
          done(err);
          return;
        }
        expect(res.header.location).to.equal('https://velopert.com');

        done();
      })
  })
})

describe('POST /user/signup', () => {
  it('should respond user info to signup data', (done) => {
    request(app)
    .post('/user/signup')
    .send({
      'email': 'test@gmail.com',
      'username': 'testuser',
      'password': 'asdfasdf'
     })
    .expect(200)
    .end((err, res) => {
      if(err) {
        done(err);
        return;
      }

      expect(res.body).has.all.keys([
        'id', 'email','password', 'username', 'updatedAt', 'createdAt'
      ])
      done();
    })
  })
})

describe('POST /user/signin', () => {
  it('should respond user id to signin data', (done) => {
    agent
      .post('/user/signin')
      .send({
        'email': 'test@gmail.com',
        'password': 'asdfasdf'
      })
      .end((err, res) => {

        expect(res.body).has.all.keys([
          'id'
        ])
        done()
      })
  })
})

describe('GET /user/info', () => {
  it('should return user data to session.userid', (done) => {
    agent
      .get('/user/info')
      .end((err, res) => {
        if(err) {
          done(err);
          return;
        }

        expect(res.body).has.all.keys([
          'id', 'email','password', 'username', 'updatedAt', 'createdAt'
        ])

        done();
      })
  })
})

describe('POST /user/signout', () => {
  it('should redirect {BASE_URL}\/ to signout', (done) => {
    agent
      .post('/user/signout')
      .end((err, res) => {
        if(err) {
          done(err);
          return;
        }

        expect(res.redirects).to.not.an('undefined')

        done();
      })
  })
})