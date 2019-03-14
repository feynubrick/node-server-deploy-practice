const express = require('express');
const http = require('http');
const bodyParser = require('body-parser');
const cors = require('cors');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');

const urls = require('./models').urls;
const users = require('./models').users;

const utils = require('./modules/utils');

const app = express();
const port = 3001;

/**
 * session(option)
 * secret - session hijacking을 막기위해 hash값에 추가로 들어가는 값 (Salt와 비슷한 개념)
 * resave - session을 언제나 저장할지 정하는 값
 * saveUninitialize: true - 세션이 저장되기 전에 uninitialized 상태로 만들어 저장
 * cookie/ secure - default는 true로 https상에서 통신할 때 정상적으로 
 *  */ 
app.use(session({
  secret: '@codestates',
  resave: false,
  saveUninitialized: true
}));

/**
 * cookieParser() - 넘어온 Cookie 데이터를 관리하기 쉽게 JSON 객체로 변환해 주는 라이브러리
 */
app.use(cookieParser());

/**
 * bodyparser.json() - body로 넘어온 데이터를 JSON 객체로 변환
 */
app.use(bodyParser.json());

/**
 * bodyParser.urlencoded({ extended }) - 중첩 객체를 허용할지 말지를 결정하는 옵션
 * 참고 링크(https://stackoverflow.com/questions/29960764/what-does-extended-mean-in-express-4-0/45690436#45690436)
 */
app.use(bodyParser.urlencoded({ extended: false }));

/**
 * cors() - CORS를 대응하기 위한 라이브러리 ( Access-Control-Allow-Origin: * )
 * https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
 */
var blacklist = [];
app.use(cors({
  origin: function (origin, callback) {
    if (blacklist.includes(origin)) {
      callback(new Error('Not allowed by CORS'))
    } else {
      callback(null, true)
    }
  },
  methods:['GET','POST', 'OPTIONS'],
}));


var corsOptions = {
  
}

/**
 * 비밀번호 hash에 추가로 넣을 salt카를 설정 express 자체에 세팅 app.set(key, value)
 */
app.set('crypto-secret', 'thisismysecretkey')

app.get('/', (req, res) => {            // function (req, res) { }
  res.status(200).send('Success')       // OK
})

app.post('/user/signup', (req, res) => {
  const data = req.body;                // const { email, password, username } = req.body.data; 로 이후 쓰일 데이터에서 data. 제거 가능 

  users
    .create({
      email: data.email,
      password: crypto                  
        .createHmac('sha512', app.get('crypto-secret'))     // hash 알고리즘 및 salt 설정
        .update(data.password)                              // hashing 할 데이터 
        .digest('base64'),                                  // 반환 값의 인코딩 방식
      username: data.username
    })
    .then(result => {
      res.status(200).json(result)
    })
})

app.post('/user/signin', (req, res) => {
  const data = req.body;
  var sess = req.session                                // req.session data를 확인 (생성 또는 기존 session이 존재하면 가져온다)

  users
    .findOne({
      where: {
        email: data.email,
        password: crypto                                    // 같은 방식의 hashing으로 변환된 값을 비교하여 반환
          .createHmac('sha512', app.get('crypto-secret'))     
          .update(data.password)                              
          .digest('base64'), 
      }
    })
    .then(result => {
      if(result === null) {                                   // 비밀번호나 이메일이 틀렸을 경우 404(Not Found) 반환
        res.sendStatus(404);
      } else {
        sess.userid = result.id;                              // 찾은 유저 id 값을 session userid 값을 매핑
        console.log(sess);
        res.status(200).json({
          id: result.id
        })
      }
    })
})

app.post('/user/signout', (req, res) => {
  const sess = req.session;                                 // session 정보를 가져온다 ( 이 경우는 데이터를 넘겨주지 않아도 이미 생성된 session값이 존재하기 때문에 생성을 하지않고 데이터를 반환)
  console.log(sess);
  if(sess.userid) {                                         // 로그인(세션 생성)이 되지않은 상태에서 불러오면 userid값이 존재하지 않는다
    req.session.destroy((err) => {                          // session을 제거하기 위한 함수로 인자는 function을 넘겨주면 된다
      if(err) {
        console.log(err);
      } else {
        console.log('found session')
        res.redirect('/');                                  // session이 성공적으로 존재하며 session 삭제가 완료되면 클라이언트에서 다시 `${URL}/`로 페이지를 이동시킨다
      }
    })
  } else {
    console.log('not found session')
    res.redirect('/');
  }
})

// GET localhost:3001/user/info

app.get('/user/info', (req, res) => {
  const sess = req.session;

  if(sess.userid) {                                         // userid를 따로 body나 query, param에 넣지 않아도 서버 자체의 세션에 저장된 userid를 가져와 데이터를 반환한다
    users
    .findOne({
      where: {
        id: sess.userid
      }
    }).then(result => {
      if(result) {
        req.session.destroy((err) => {
          if(err) {
            console.log(err);
          } else {
            res.status(200).json(result)
          }
        })
      } else {
        res.sendStatus(204)
      }
    }).catch(error => {
      res.sendStatus(500)
    })
  } else {
    res.sendStatus(401).send('need user session')
  }
})

app.get('/links', (req, res) => {
  urls
    .findAll()
    .then(result => {
      if(result) {
        res.status(200).json(result)    // OK
      } else {
        res.sendStatus(204);            // No Content
      }
    })
    .catch(error => {
      console.log(error)
      res.status(500).send(error)       // Server error
    })
})

app.post('/links', (req, res) => {
  const { url } = req.body;             // const url = req.body.url

  if(!utils.isValidUrl(url)) {          // URL 형태 체크 함수 ( 정규식으로 이루어져있다 )
    return res.sendStatus(400)          // Bad Request
  }

  utils.getUrlTitle(url, (err, title) => {      // shorten URL 생성 함수 
    if(err) {
      console.log(err)
      return res.sendStatus(400)
    }

    urls
      .create({
        url: url,
        baseUrl: req.headers.host,
        title: title
      })
      .then(result => {
        res.status(201).json(result)      // Created
      })
      .catch(error => {
        console.log(error)
        res.sendStatus(500)               // Server error
      })
  });
})

app.get('/*', (req, res) => {
  urls
    .findOne({
      where: {
          code: req.params[0]                   // req.params는 url중 도메인 명 다음부터 쌓인다 ( https://naver.com/params[0]/params[1]/params[2])
      }
    })
    .then(result => {
      if(result) {
        result.updateAttributes({               // sequelize에서 반환되는 데이터는 단순히 결과값의 데이터 객체가 아니라 sequelize의 함수를 포함하고 있다. 
          visits: result.visits + 1             // 다만 데이터에 접근할 경우에는 바로 접근 가능
        })
        res.redirect(result.url)
      } else {
        res.sendStatus(204)                 // No Content
      }
    })
    .catch(error => {
      console.log(error)
      res.sendStatus(500)                   // Server Error
    })
})

app.set('port', port)
app.listen(app.get('port'));

module.exports = app;
